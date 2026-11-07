"""Small durable JSON-state adapter for TiDB Cloud / MySQL.

When TIDB_* settings are absent, local JSON files are used for development.
When configured, database failures are raised instead of silently falling back
and pretending that writes are durable.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

_LOCK = threading.RLock()
_TABLE = "rafin_app_state"
_TELEGRAM_EVENTS_TABLE = "alz3by_telegram_update_receipts"
_TELEGRAM_EVENTS_READY = False
_LOCAL_TELEGRAM_UPDATES: set[int] = set()
_LOCAL_TELEGRAM_UPDATE_ORDER: list[int] = []
_CA_DEFAULT = "/etc/ssl/certs/ca-certificates.crt"


class StoreError(RuntimeError):
    pass


def database_configured() -> bool:
    names = ("TIDB_HOST", "TIDB_PORT", "TIDB_USER", "TIDB_PASSWORD", "TIDB_DB_NAME")
    return any(os.environ.get(name) for name in names)


def _config() -> dict[str, Any]:
    values = {
        "host": os.environ.get("TIDB_HOST", "").strip(),
        "port": os.environ.get("TIDB_PORT", "4000").strip(),
        "user": os.environ.get("TIDB_USER", "").strip(),
        "password": os.environ.get("TIDB_PASSWORD", ""),
        "database": os.environ.get("TIDB_DB_NAME", "").strip(),
    }
    missing = [key for key in ("host", "user", "password", "database") if not values[key]]
    if missing:
        raise StoreError("TiDB settings are incomplete; set TIDB_HOST, TIDB_USER, TIDB_PASSWORD, and TIDB_DB_NAME in the service environment.")
    try:
        values["port"] = int(values["port"])
    except ValueError as exc:
        raise StoreError("TIDB_PORT must be a valid port number.") from exc
    ca_path = os.environ.get("TIDB_SSL_CA", _CA_DEFAULT).strip()
    if not ca_path or not Path(ca_path).is_file():
        raise StoreError("TiDB TLS CA file was not found; set TIDB_SSL_CA to the system CA bundle path.")
    values["ssl_ca"] = ca_path
    return values


def _connect():
    try:
        import mysql.connector
    except ImportError as exc:
        raise StoreError("mysql-connector-python is required when TiDB is configured.") from exc
    try:
        return mysql.connector.connect(
            **_config(),
            autocommit=True,
            connection_timeout=10,
            use_pure=True,
            ssl_verify_cert=True,
            ssl_verify_identity=True,
        )
    except StoreError:
        raise
    except Exception as exc:
        # Do not propagate provider exceptions that might include connection details.
        raise StoreError(f"Could not connect to TiDB ({type(exc).__name__}). Check the Render environment and TiDB network allowlist.") from exc


def initialize() -> bool:
    """Create the state table; return False when local-file mode is active."""
    if not database_configured():
        return False
    with _LOCK:
        conn = _connect()
        try:
            cur = conn.cursor()
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "state_key VARCHAR(64) PRIMARY KEY, "
                "payload LONGTEXT NOT NULL, "
                "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
                "ON UPDATE CURRENT_TIMESTAMP)"
            )
            cur.close()
        except Exception as exc:
            raise StoreError(f"Could not initialize TiDB state table ({type(exc).__name__}).") from exc
        finally:
            conn.close()
    return True


def claim_telegram_update(update_id: int) -> bool:
    """Atomically claim a Telegram update ID so webhook retries are harmless."""
    global _TELEGRAM_EVENTS_READY
    try:
        update_id = int(update_id)
    except (TypeError, ValueError) as exc:
        raise StoreError("Telegram update ID is invalid.") from exc
    if update_id < 0:
        raise StoreError("Telegram update ID is invalid.")
    with _LOCK:
        if not database_configured():
            if update_id in _LOCAL_TELEGRAM_UPDATES:
                return False
            _LOCAL_TELEGRAM_UPDATES.add(update_id)
            _LOCAL_TELEGRAM_UPDATE_ORDER.append(update_id)
            if len(_LOCAL_TELEGRAM_UPDATES) > 10000:
                oldest = _LOCAL_TELEGRAM_UPDATE_ORDER.pop(0)
                _LOCAL_TELEGRAM_UPDATES.discard(oldest)
            return True
        conn = _connect()
        try:
            cur = conn.cursor()
            if not _TELEGRAM_EVENTS_READY:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {_TELEGRAM_EVENTS_TABLE} ("
                    "update_id BIGINT NOT NULL PRIMARY KEY, "
                    "received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
                )
                _TELEGRAM_EVENTS_READY = True
            cur.execute(
                f"INSERT IGNORE INTO {_TELEGRAM_EVENTS_TABLE} (update_id) VALUES (%s)",
                (update_id,),
            )
            claimed = cur.rowcount == 1
            cur.close()
            return claimed
        except Exception as exc:
            raise StoreError(f"Could not record Telegram update ({type(exc).__name__}).") from exc
        finally:
            conn.close()



def _read_file(path: str | os.PathLike[str], default: Any, decoder: Callable[[Any], Any] | None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        return decoder(value) if decoder else value
    except FileNotFoundError:
        return default


def load_json(
    key: str,
    path: str | os.PathLike[str],
    default: Any,
    *,
    decoder: Callable[[Any], Any] | None = None,
    encoder: Callable[[Any], Any] | None = None,
) -> Any:
    """Load state from TiDB, seeding it from the legacy JSON file if absent."""
    with _LOCK:
        if database_configured():
            conn = _connect()
            try:
                cur = conn.cursor()
                cur.execute(f"SELECT payload FROM {_TABLE} WHERE state_key = %s", (key,))
                row = cur.fetchone()
                cur.close()
            except Exception as exc:
                raise StoreError(f"Could not read TiDB state ({type(exc).__name__}).") from exc
            finally:
                conn.close()
            if row is not None:
                value = json.loads(row[0])
                return decoder(value) if decoder else value
            # One-time migration from an existing local JSON file.
            value = _read_file(path, default, decoder)
            save_json(key, path, value, encoder=encoder)
            return value
        return _read_file(path, default, decoder)


def save_json(
    key: str,
    path: str | os.PathLike[str],
    value: Any,
    *,
    encoder: Callable[[Any], Any] | None = None,
) -> None:
    """Save a JSON value to TiDB or atomically to the local development file."""
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=encoder)
    with _LOCK:
        if database_configured():
            conn = _connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    f"INSERT INTO {_TABLE} (state_key, payload) VALUES (%s, %s) "
                    "ON DUPLICATE KEY UPDATE payload = %s",
                    (key, payload, payload),
                )
                cur.close()
            except Exception as exc:
                raise StoreError(f"Could not save TiDB state ({type(exc).__name__}).") from exc
            finally:
                conn.close()
            return

        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{file_path.name}.", dir=str(file_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, default=encoder)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, file_path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
