"""Telegram OpenID Connect login for the aiohttp dashboard.

Secrets and redirect configuration are read at request time from environment
variables. No bot credentials or session signing keys belong in source control.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import aiohttp
import jwt
from aiohttp import web

ISSUER = "https://oauth.telegram.org"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/auth"
TOKEN_ENDPOINT = f"{ISSUER}/token"
JWKS_ENDPOINT = f"{ISSUER}/.well-known/jwks.json"
TX_COOKIE = "tg_oidc_transaction"
SESSION_COOKIE = "tg_dashboard_session"
TX_TTL_SECONDS = 600
SESSION_TTL_SECONDS = 8 * 60 * 60
CLOCK_SKEW_SECONDS = 30
MAX_ID_TOKEN_AGE_SECONDS = 600


class TelegramAuthError(Exception):
    """Expected authentication failure with a non-sensitive internal code."""


class TelegramAuth:
    def __init__(self) -> None:
        self._jwks: list[dict[str, Any]] = []
        self._jwks_cached_at = 0.0

    @staticmethod
    def _settings() -> dict[str, Any]:
        client_id = os.environ.get("TELEGRAM_CLIENT_ID", "").strip()
        client_secret = os.environ.get("TELEGRAM_CLIENT_SECRET", "").strip()
        redirect_uri = os.environ.get("TELEGRAM_REDIRECT_URI", "").strip()
        session_secret = os.environ.get("TELEGRAM_SESSION_SECRET", "").encode("utf-8")
        allowed_ids = {
            item.strip() for item in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
            if item.strip()
        }
        try:
            parsed_redirect = urlsplit(redirect_uri)
            redirect_ok = (
                parsed_redirect.scheme == "https"
                and bool(parsed_redirect.netloc)
                and parsed_redirect.path == "/auth/telegram/callback"
                and not parsed_redirect.query
                and not parsed_redirect.fragment
                and parsed_redirect.username is None
                and parsed_redirect.password is None
            )
        except Exception:
            redirect_ok = False
        enabled = bool(
            client_id and client_id.isdigit() and client_secret
            and len(session_secret) >= 32 and allowed_ids and redirect_ok
        )
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "session_secret": session_secret,
            "allowed_ids": allowed_ids,
            "enabled": enabled,
        }

    @staticmethod
    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _b64u_decode(value: str) -> bytes:
        if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("bad base64url")
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    @classmethod
    def _sign_payload(cls, payload: dict[str, Any], secret: bytes, purpose: str) -> str:
        encoded = cls._b64u(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        message = f"telegram-dashboard:{purpose}:{encoded}".encode("ascii")
        signature = hmac.new(secret, message, hashlib.sha256).digest()
        return f"{encoded}.{cls._b64u(signature)}"

    @classmethod
    def _verify_payload(cls, value: str, secret: bytes, purpose: str) -> dict[str, Any] | None:
        try:
            encoded, supplied_signature = value.split(".", 1)
            message = f"telegram-dashboard:{purpose}:{encoded}".encode("ascii")
            expected_signature = hmac.new(secret, message, hashlib.sha256).digest()
            supplied = cls._b64u_decode(supplied_signature)
            if not hmac.compare_digest(supplied, expected_signature):
                return None
            payload = json.loads(cls._b64u_decode(encoded).decode("utf-8"))
            return payload if isinstance(payload, dict) else None
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _expected_origin() -> str:
        redirect_uri = os.environ.get("TELEGRAM_REDIRECT_URI", "").strip()
        parsed = urlsplit(redirect_uri)
        if parsed.scheme != "https" or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def get_session(self, request: web.Request) -> dict[str, Any] | None:
        settings = self._settings()
        if not settings["enabled"]:
            return None
        raw = request.cookies.get(SESSION_COOKIE, "")
        payload = self._verify_payload(raw, settings["session_secret"], "session")
        if not payload:
            return None
        try:
            now = int(time.time())
            issued = int(payload.get("iat", 0))
            expires = int(payload.get("exp", 0))
            user_id = str(payload.get("id", ""))
            if (not user_id.isdigit() or user_id not in settings["allowed_ids"]
                    or expires <= now or issued > now + CLOCK_SKEW_SECONDS
                    or now - issued > SESSION_TTL_SECONDS + CLOCK_SKEW_SECONDS):
                return None
            return {
                "id": user_id,
                "username": str(payload.get("username", ""))[:64],
                "name": str(payload.get("name", ""))[:128],
                "iat": issued,
                "exp": expires,
            }
        except (TypeError, ValueError):
            return None

    async def session_info(self, request: web.Request) -> web.Response:
        settings = self._settings()
        session = self.get_session(request)
        response = web.json_response({
            "authenticated": bool(session),
            "telegram_login_enabled": settings["enabled"],
            "user": ({
                "id": session["id"],
                "username": session["username"],
                "name": session["name"],
            } if session else None),
        })
        response.headers["Cache-Control"] = "no-store"
        if request.cookies.get(SESSION_COOKIE) and not session:
            response.del_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return response

    async def start(self, request: web.Request) -> web.Response:
        settings = self._settings()
        if not settings["enabled"]:
            return web.HTTPFound("/?auth=not_configured")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = self._b64u(hashlib.sha256(verifier.encode("ascii")).digest())
        now = int(time.time())
        transaction = self._sign_payload({
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "iat": now,
        }, settings["session_secret"], "transaction")
        params = {
            "client_id": settings["client_id"],
            "redirect_uri": settings["redirect_uri"],
            "response_type": "code",
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        response = web.HTTPFound(f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}")
        response.set_cookie(
            TX_COOKIE, transaction, max_age=TX_TTL_SECONDS, path="/auth/telegram",
            secure=True, httponly=True, samesite="Lax",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def _exchange_code(self, code: str, settings: dict[str, Any], verifier: str) -> dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=15)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings["redirect_uri"],
            "client_id": settings["client_id"],
            "code_verifier": verifier,
        }
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    TOKEN_ENDPOINT, data=data,
                    auth=aiohttp.BasicAuth(settings["client_id"], settings["client_secret"]),
                    headers={"Accept": "application/json"},
                ) as response:
                    if response.status != 200:
                        raise TelegramAuthError("token_exchange_failed")
                    token_data = await response.json(content_type=None)
            if not isinstance(token_data, dict) or not token_data.get("id_token"):
                raise TelegramAuthError("missing_id_token")
            return token_data
        except TelegramAuthError:
            raise
        except Exception as exc:
            raise TelegramAuthError("token_exchange_failed") from exc

    async def _fetch_jwks(self, force: bool = False) -> list[dict[str, Any]]:
        now = time.time()
        if self._jwks and not force and now - self._jwks_cached_at < 3600:
            return self._jwks
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(JWKS_ENDPOINT, headers={"Accept": "application/json"}) as response:
                    if response.status != 200:
                        raise TelegramAuthError("jwks_unavailable")
                    document = await response.json(content_type=None)
            keys = document.get("keys", []) if isinstance(document, dict) else []
            if not isinstance(keys, list) or not keys or len(keys) > 32:
                raise TelegramAuthError("jwks_invalid")
            self._jwks = [item for item in keys if isinstance(item, dict)]
            self._jwks_cached_at = now
            return self._jwks
        except TelegramAuthError:
            raise
        except Exception as exc:
            raise TelegramAuthError("jwks_unavailable") from exc

    async def validate_id_token(
        self, encoded_token: str, settings: dict[str, Any], expected_nonce: str,
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(encoded_token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise TelegramAuthError("unsupported_id_token")
            keys = await self._fetch_jwks()
            jwk = next((item for item in keys if item.get("kid") == header["kid"]), None)
            if jwk is None:
                keys = await self._fetch_jwks(force=True)
                jwk = next((item for item in keys if item.get("kid") == header["kid"]), None)
            if not jwk or jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig":
                raise TelegramAuthError("signing_key_not_found")
            public_key = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key
            claims = jwt.decode(
                encoded_token,
                public_key,
                algorithms=["RS256"],
                audience=settings["client_id"],
                issuer=ISSUER,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce"]},
            )
            now = int(time.time())
            issued = int(claims["iat"])
            if issued > now + CLOCK_SKEW_SECONDS or now - issued > MAX_ID_TOKEN_AGE_SECONDS:
                raise TelegramAuthError("id_token_time_invalid")
            if not hmac.compare_digest(str(claims.get("nonce", "")), expected_nonce):
                raise TelegramAuthError("nonce_mismatch")
            subject = str(claims.get("sub", ""))
            user_id = str(claims.get("id", subject))
            if not subject or not user_id.isdigit() or int(user_id) <= 0:
                raise TelegramAuthError("telegram_user_id_invalid")
            claims["_telegram_user_id"] = user_id
            return claims
        except TelegramAuthError:
            raise
        except Exception as exc:
            raise TelegramAuthError("id_token_validation_failed") from exc

    @staticmethod
    def _redirect_result(result: str, transaction_cookie: bool = True) -> web.Response:
        response = web.HTTPFound(f"/?auth={result}")
        if transaction_cookie:
            response.del_cookie(TX_COOKIE, path="/auth/telegram", secure=True, httponly=True, samesite="Lax")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def callback(self, request: web.Request) -> web.Response:
        settings = self._settings()
        if not settings["enabled"]:
            return self._redirect_result("not_configured")
        if request.query.get("error"):
            return self._redirect_result("cancelled")

        transaction = self._verify_payload(
            request.cookies.get(TX_COOKIE, ""), settings["session_secret"], "transaction",
        )
        state = request.query.get("state", "")
        code = request.query.get("code", "")
        if not transaction or not state or not code:
            return self._redirect_result("failed")
        try:
            created_at = int(transaction.get("iat", 0))
        except (TypeError, ValueError):
            return self._redirect_result("failed")
        now = int(time.time())
        if (now - created_at < 0 or now - created_at > TX_TTL_SECONDS
                or not hmac.compare_digest(str(transaction.get("state", "")), state)):
            return self._redirect_result("failed")

        try:
            token_data = await self._exchange_code(code, settings, str(transaction.get("verifier", "")))
            claims = await self.validate_id_token(
                str(token_data["id_token"]), settings, str(transaction.get("nonce", "")),
            )
            user_id = claims["_telegram_user_id"]
            if user_id not in settings["allowed_ids"]:
                return self._redirect_result("denied")
            username = str(claims.get("preferred_username", ""))[:64]
            name = str(claims.get("name", ""))[:128]
            session_payload = {
                "id": user_id,
                "username": username,
                "name": name,
                "iat": now,
                "exp": now + SESSION_TTL_SECONDS,
            }
            signed_session = self._sign_payload(session_payload, settings["session_secret"], "session")
            response = self._redirect_result("success")
            response.set_cookie(
                SESSION_COOKIE, signed_session, max_age=SESSION_TTL_SECONDS, path="/",
                secure=True, httponly=True, samesite="Lax",
            )
            return response
        except TelegramAuthError as exc:
            # Error codes are deliberately generic and never include codes, tokens, or secrets.
            print(f"[TG-AUTH] {exc}")
            return self._redirect_result("failed")
        except Exception:
            print("[TG-AUTH] unexpected_callback_failure")
            return self._redirect_result("failed")

    async def logout(self, request: web.Request) -> web.Response:
        expected_origin = self._expected_origin()
        supplied_origin = request.headers.get("Origin", "").rstrip("/")
        if not expected_origin or not hmac.compare_digest(supplied_origin, expected_origin):
            return web.json_response({"ok": False, "error": "Invalid request origin"}, status=403)
        response = web.json_response({"ok": True})
        response.del_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        response.del_cookie(TX_COOKIE, path="/auth/telegram", secure=True, httponly=True, samesite="Lax")
        response.headers["Cache-Control"] = "no-store"
        return response

    def cookie_write_allowed(self, request: web.Request) -> bool:
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return True
        expected_origin = self._expected_origin()
        supplied_origin = request.headers.get("Origin", "").rstrip("/")
        return bool(expected_origin and hmac.compare_digest(supplied_origin, expected_origin))


telegram_auth = TelegramAuth()
