"""Private Telegram control bot for the existing aiohttp dashboard.

The bot deliberately delegates state-changing work to the dashboard API handlers.
It never accepts or sends account passwords, tokens, or credential files.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import time
from typing import Any, Awaitable, Callable

import httpx
from aiohttp import web

_LOG = logging.getLogger("telegram_bot")
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_INTERACTIVE_TIMEOUT = httpx.Timeout(4.0, connect=2.0, read=3.0, write=3.0, pool=1.0)
_SETUP_TIMEOUT = httpx.Timeout(12.0, connect=5.0)
_REGION_NAMES = {
    "BD": "Bangladesh", "IND": "India", "ID": "Indonesia", "ME": "Middle East",
    "PK": "Pakistan", "VN": "Vietnam", "TH": "Thailand", "TW": "Taiwan",
    "RU": "Russia", "SAC": "South America", "BR": "Brazil", "NA": "North America",
    "SG": "Singapore", "US": "United States",
}
_REGION_CODES = tuple(_REGION_NAMES)
_ACCOUNT_PAGE_SIZE = 5


class InternalRequest:
    """Small adapter used to invoke the exact aiohttp API handlers internally."""
    def __init__(self, payload: dict[str, Any] | None = None):
        self._payload = payload or {}

    async def json(self) -> dict[str, Any]:
        return self._payload


class TelegramBot:
    def __init__(
        self,
        actions: dict[str, Callable[[Any], Awaitable[web.StreamResponse]]],
        state_store: Any,
    ):
        self.actions = actions
        self.state_store = state_store
        self.token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        self.secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
        self.webhook_url = os.environ.get("TELEGRAM_WEBHOOK_URL", "").strip()
        self.allowed_ids = {
            item.strip() for item in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
            if item.strip().isdigit() and int(item.strip()) > 0
        }
        self.client: httpx.AsyncClient | None = None
        self._memory_updates: set[int] = set()
        self._memory_update_order: list[int] = []
        self._update_lock = asyncio.Lock()
        self._flows: dict[str, dict[str, Any]] = {}
        self._started = False

    @property
    def ready(self) -> bool:
        return bool(
            self.token and self.secret and _SECRET_RE.fullmatch(self.secret)
            and self.webhook_url.startswith("https://") and self.allowed_ids
        )

    async def startup(self) -> None:
        if not self.ready:
            missing = []
            if not self.token: missing.append("TELEGRAM_BOT_TOKEN")
            if not self.secret or not _SECRET_RE.fullmatch(self.secret): missing.append("TELEGRAM_WEBHOOK_SECRET")
            if not self.webhook_url.startswith("https://"): missing.append("TELEGRAM_WEBHOOK_URL")
            if not self.allowed_ids: missing.append("TELEGRAM_ALLOWED_USER_IDS")
            _LOG.info("Telegram bot disabled or incomplete; missing/invalid settings: %s", ",".join(missing))
            return
        self.client = httpx.AsyncClient(timeout=_INTERACTIVE_TIMEOUT)
        try:
            result = await self._telegram("setWebhook", {
                "url": self.webhook_url,
                "secret_token": self.secret,
                "allowed_updates": ["message", "callback_query"],
                "drop_pending_updates": False,
            }, timeout=_SETUP_TIMEOUT)
            if result.get("ok"):
                await self._telegram("setMyCommands", {"commands": [
                    {"command": "start", "description": "فتح القائمة الرئيسية"},
                    {"command": "help", "description": "عرض المساعدة"},
                    {"command": "menu", "description": "القائمة الرئيسية"},
                    {"command": "accounts", "description": "حالة الحسابات"},
                    {"command": "teams", "description": "عرض الفرق"},
                    {"command": "matches", "description": "حالة دورة المباريات"},
                    {"command": "logs", "description": "آخر سجلات الخدمة"},
                    {"command": "cancel", "description": "إلغاء العملية الحالية"},
                ]}, timeout=_SETUP_TIMEOUT)
                self._started = True
                _LOG.info("Telegram webhook configured successfully")
            else:
                _LOG.error("Telegram webhook setup rejected; error code=%s", result.get("error_code", "unknown"))
        except Exception as exc:
            _LOG.error("Telegram webhook setup failed (%s)", type(exc).__name__)

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()
            self.client = None

    async def _telegram(
        self, method: str, payload: dict[str, Any], *, timeout: httpx.Timeout | None = None,
    ) -> dict[str, Any]:
        if not self.client or not self.token:
            return {"ok": False, "description": "bot_not_configured"}
        request_args: dict[str, Any] = {"json": payload}
        if timeout is not None:
            request_args["timeout"] = timeout
        response = await self.client.post(
            f"https://api.telegram.org/bot{self.token}/{method}", **request_args,
        )
        try:
            data = response.json()
        except Exception:
            data = {}
        if response.status_code >= 400 or not isinstance(data, dict):
            return {"ok": False, "error_code": response.status_code}
        return data

    async def _claim_update(self, update_id: int) -> bool:
        async with self._update_lock:
            try:
                claim = getattr(self.state_store, "claim_telegram_update", None)
                if claim:
                    return bool(claim(update_id))
            except Exception:
                # Do not acknowledge updates when durable deduplication is unavailable.
                raise
            if update_id in self._memory_updates:
                return False
            self._memory_updates.add(update_id)
            self._memory_update_order.append(update_id)
            if len(self._memory_update_order) > 10000:
                old = self._memory_update_order.pop(0)
                self._memory_updates.discard(old)
            return True

    async def webhook(self, request: web.Request) -> web.Response:
        if not self.ready:
            return web.json_response({"ok": False}, status=503)
        supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not hmac.compare_digest(supplied, self.secret):
            return web.json_response({"ok": False}, status=403)
        if request.content_length is not None and request.content_length > 256 * 1024:
            return web.json_response({"ok": False}, status=413)
        try:
            raw = await request.read()
            if len(raw) > 256 * 1024:
                return web.json_response({"ok": False}, status=413)
            update = json.loads(raw.decode("utf-8"))
            update_id = update.get("update_id") if isinstance(update, dict) else None
            if type(update_id) is not int or update_id < 0:
                return web.json_response({"ok": False}, status=400)
            if not await self._claim_update(update_id):
                return web.json_response({"ok": True, "duplicate": True})
            try:
                await self._dispatch(update)
            except Exception as exc:
                _LOG.error("Telegram update processing failed; update_id=%s type=%s", update_id, type(exc).__name__)
            return web.json_response({"ok": True})
        except (UnicodeDecodeError, json.JSONDecodeError):
            return web.json_response({"ok": False}, status=400)
        except Exception as exc:
            _LOG.error("Telegram webhook unavailable (%s)", type(exc).__name__)
            return web.json_response({"ok": False}, status=503)

    async def _dispatch(self, update: dict[str, Any]) -> None:
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            await self._handle_callback(callback)
            return
        message = update.get("message")
        if isinstance(message, dict):
            await self._handle_message(message)

    @staticmethod
    def _sender_id(message_or_query: dict[str, Any]) -> str:
        user = message_or_query.get("from") or {}
        value = user.get("id")
        return str(value) if isinstance(value, int) and value > 0 else ""

    def _is_private_owner(self, user_id: str, chat: dict[str, Any] | None) -> bool:
        return bool(
            user_id in self.allowed_ids and isinstance(chat, dict)
            and chat.get("type") == "private" and str(chat.get("id")) == user_id
        )

    async def _handle_message(self, message: dict[str, Any]) -> None:
        user_id = self._sender_id(message)
        chat = message.get("chat") or {}
        if not self._is_private_owner(user_id, chat):
            return
        chat_id = str(chat["id"])
        text = message.get("text")
        if not isinstance(text, str):
            await self._send(chat_id, "أرسل أمرًا نصيًا أو استخدم أزرار القائمة. لا ترسل كلمات مرور أو ملفات اعتماد إلى البوت.", self._menu_keyboard())
            return
        command = text.strip().split(maxsplit=1)[0].split("@", 1)[0].lower() if text.strip().startswith("/") else ""
        if command in {"/start", "/menu", "/help"}:
            self._flows.pop(user_id, None)
            await self._send(chat_id, "مرحبًا بك في لوحة AlZ3By. اختر الإجراء من القائمة. تبقى كلمات المرور والاستيراد والتصدير على الموقع فقط.", self._menu_keyboard())
        elif command == "/cancel":
            self._flows.pop(user_id, None)
            await self._send(chat_id, "تم إلغاء العملية.", self._menu_keyboard())
        elif command == "/accounts":
            await self._show_accounts(chat_id, 0)
        elif command == "/teams":
            await self._show_teams(chat_id)
        elif command == "/matches":
            await self._show_cycle(chat_id)
        elif command == "/logs":
            await self._show_logs(chat_id)
        elif user_id in self._flows and self._flows[user_id].get("step") == "clan_id":
            await self._receive_clan_id(chat_id, user_id, text.strip())
        else:
            await self._send(chat_id, "الأمر غير معروف. استخدم /help لعرض الخيارات.", self._menu_keyboard())

    async def _handle_callback(self, query: dict[str, Any]) -> None:
        user_id = self._sender_id(query)
        message = query.get("message") or {}
        chat = message.get("chat") or {}
        if not self._is_private_owner(user_id, chat):
            await self._answer_callback(query.get("id"), "غير مصرح", alert=True)
            return
        await self._answer_callback(query.get("id"))
        data = query.get("data")
        if not isinstance(data, str) or len(data) > 64:
            return
        chat_id = str(chat["id"])
        parts = data.split(":")
        if data == "menu:home":
            self._flows.pop(user_id, None)
            await self._send(chat_id, "القائمة الرئيسية", self._menu_keyboard())
        elif data == "menu:accounts":
            await self._show_accounts(chat_id, 0)
        elif data.startswith("accounts:page:"):
            try: page = max(0, int(parts[2]))
            except (IndexError, ValueError): return
            await self._show_accounts(chat_id, page)
        elif data == "menu:teams":
            await self._show_teams(chat_id)
        elif data == "menu:cycle":
            await self._show_cycle(chat_id)
        elif data == "menu:logs":
            await self._show_logs(chat_id)
        elif data == "menu:create":
            self._flows[user_id] = {"step": "region"}
            rows = [[{"text": f"{code} — {_REGION_NAMES[code]}", "callback_data": f"create:region:{code}"}] for code in _REGION_CODES]
            rows.append([{"text": "إلغاء", "callback_data": "create:cancel"}])
            await self._send(chat_id, "اختر منطقة الحسابات الجديدة:", {"inline_keyboard": rows})
        elif data.startswith("create:region:"):
            region = parts[2].upper() if len(parts) == 3 else ""
            if region not in _REGION_NAMES: return
            self._flows[user_id] = {"step": "clan_choice", "region": region}
            await self._send(chat_id, f"اختر معرّف الكلان لمنطقة {region}:", {"inline_keyboard": [
                [{"text": "استخدام الكلان 3106587789", "callback_data": "create:defaultclan"}],
                [{"text": "إدخال معرّف آخر", "callback_data": "create:customclan"}],
                [{"text": "إلغاء", "callback_data": "create:cancel"}],
            ]})
        elif data == "create:defaultclan":
            flow = self._flows.get(user_id, {})
            if flow.get("step") != "clan_choice": return
            flow["clan_id"] = "3106587789"
            flow["step"] = "count"
            await self._send_count_options(chat_id)
        elif data == "create:customclan":
            flow = self._flows.get(user_id, {})
            if flow.get("step") != "clan_choice": return
            flow["step"] = "clan_id"
            await self._send(chat_id, "أرسل معرّف الكلان كأرقام فقط، أو استخدم /cancel للإلغاء.")
        elif data == "create:cancel":
            self._flows.pop(user_id, None)
            await self._send(chat_id, "تم إلغاء إنشاء الفريق.", self._menu_keyboard())
        elif data.startswith("create:count:"):
            try: count = int(parts[2])
            except (IndexError, ValueError): return
            flow = self._flows.get(user_id, {})
            if flow.get("step") != "count" or count not in (2, 3, 4): return
            flow["count"] = count
            flow["step"] = "confirm_team"
            clan_id = flow.get("clan_id", "")
            region = flow.get("region", "ID")
            await self._send(chat_id, f"تأكيد إنشاء {count} حسابات في {region} للكلان {clan_id}؟\nسيستخدم الخادم كلمة المرور الافتراضية AlZ3By دون إرسالها في المحادثة.", {
                "inline_keyboard": [[
                    {"text": "تأكيد الإنشاء", "callback_data": "create:confirm"},
                    {"text": "إلغاء", "callback_data": "create:cancel"},
                ]]
            })
        elif data == "create:confirm":
            flow = self._flows.get(user_id, {})
            if flow.get("step") != "confirm_team": return
            payload = {"region": flow["region"], "clan_id": flow["clan_id"], "count": flow["count"], "password": "AlZ3By"}
            self._flows.pop(user_id, None)
            result = await self._call("create_team", payload)
            if result.get("ok"):
                await self._send(chat_id, f"بدأ إنشاء {payload['count']} حسابات في {payload['region']} للكلان {payload['clan_id']}. ستعمل العملية في الخلفية؛ استخدم /teams لمتابعة الحالة.", self._menu_keyboard())
            else:
                await self._send(chat_id, self._api_error(result, "تعذر بدء إنشاء الفريق. تحقق من الحالة وحاول مجددًا."), self._menu_keyboard())
        elif data.startswith("account:"):
            await self._account_action(chat_id, data)
        elif data in {"confirm:pause_all", "confirm:resume_all", "confirm:clear_logs", "confirm:cycle_start", "confirm:cycle_stop"}:
            await self._confirm_global(chat_id, data)
        elif data.startswith("confirm:account:"):
            await self._confirm_account(chat_id, data)
        elif data == "menu:pause_all":
            result = await self._call("stats", {})
            accounts = result.get("accounts") or []
            all_paused = bool(accounts) and all(bool(item.get("is_paused")) or str(item.get("status", "")).upper() == "PAUSED" for item in accounts)
            action = "resume_all" if all_paused else "pause_all"
            verb = "استئناف" if all_paused else "إيقاف مؤقت لجميع"
            await self._send(chat_id, f"هل تريد {verb} الحسابات؟", {"inline_keyboard": [[
                {"text": "تأكيد", "callback_data": f"confirm:{action}"},
                {"text": "إلغاء", "callback_data": "menu:home"},
            ]]})
        elif data == "menu:cycle_start" or data == "menu:cycle_stop":
            action = "cycle_start" if data.endswith("start") else "cycle_stop"
            label = "بدء" if action == "cycle_start" else "إيقاف"
            await self._send(chat_id, f"تأكيد {label} دورة Battle Royale؟", {"inline_keyboard": [[
                {"text": "تأكيد", "callback_data": f"confirm:{action}"},
                {"text": "إلغاء", "callback_data": "menu:cycle"},
            ]]})
        elif data == "menu:clear_logs":
            await self._send(chat_id, "هل تريد مسح سجلات التشغيل الحالية؟", {"inline_keyboard": [[
                {"text": "مسح السجلات", "callback_data": "confirm:clear_logs"},
                {"text": "إلغاء", "callback_data": "menu:logs"},
            ]]})

    async def _receive_clan_id(self, chat_id: str, user_id: str, text: str) -> None:
        if text.startswith("/"):
            await self._send(chat_id, "أرسل معرّف الكلان كأرقام فقط أو استخدم /cancel.")
            return
        clan_id = text.strip()
        if not clan_id.isdigit() or not (5 <= len(clan_id) <= 20):
            await self._send(chat_id, "معرّف الكلان غير صالح. أرسل أرقامًا بطول 5 إلى 20 خانة، أو استخدم /cancel.")
            return
        flow = self._flows.get(user_id)
        if not flow or flow.get("step") != "clan_id":
            return
        flow["clan_id"] = clan_id
        flow["step"] = "count"
        await self._send_count_options(chat_id)

    async def _send_count_options(self, chat_id: str) -> None:
        await self._send(chat_id, "اختر عدد الحسابات:", {"inline_keyboard": [
            [{"text": "4 حسابات (فريق كامل)", "callback_data": "create:count:4"}],
            [{"text": "3 حسابات", "callback_data": "create:count:3"}],
            [{"text": "حسابان", "callback_data": "create:count:2"}],
            [{"text": "إلغاء", "callback_data": "create:cancel"}],
        ]})

    async def _call(self, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        handler = self.actions.get(action)
        if not handler:
            return {"error": "unsupported_action"}
        response = await handler(InternalRequest(payload))
        try:
            data = json.loads(response.text or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict): data = {}
        if response.status >= 400:
            data.setdefault("error", "request_failed")
        return data

    @staticmethod
    def _api_error(result: dict[str, Any], fallback: str) -> str:
        error = result.get("error") or result.get("message")
        if error == "already creating": return "يوجد إنشاء فريق جارٍ بالفعل. انتظر اكتماله ثم أعد المحاولة."
        if error == "clan_id required": return "معرّف الكلان مطلوب."
        return fallback

    async def _account_action(self, chat_id: str, data: str) -> None:
        parts = data.split(":")
        if len(parts) < 3: return
        action, uid = parts[1], parts[2]
        if not uid.isdigit() or action not in {"pause", "resume", "restart", "refresh", "delete"}: return
        if action in {"restart", "delete"}:
            label = "إعادة تشغيل" if action == "restart" else "حذف"
            await self._send(chat_id, f"تأكيد {label} الحساب UID {uid}؟", {"inline_keyboard": [[
                {"text": "تأكيد", "callback_data": f"confirm:account:{action}:{uid}"},
                {"text": "إلغاء", "callback_data": "menu:accounts"},
            ]]})
            return
        if action in {"pause", "resume"}:
            result = await self._call("account_pause", {"uid": uid})
            if result.get("status") == "ok":
                await self._send(chat_id, f"{'تم إيقاف' if result.get('is_paused') else 'تم استئناف'} الحساب {uid}.", self._menu_keyboard())
            else: await self._send(chat_id, self._api_error(result, "تعذر تغيير حالة الحساب."))
        elif action == "refresh":
            result = await self._call("account_refresh", {"uid": uid})
            await self._send(chat_id, "أُرسل طلب تحديث الملف الشخصي للحساب." if result.get("status") == "ok" else self._api_error(result, "تعذر تحديث الحساب."), self._menu_keyboard())

    async def _confirm_account(self, chat_id: str, data: str) -> None:
        parts = data.split(":")
        if len(parts) != 4: return
        action, uid = parts[2], parts[3]
        if action not in {"restart", "delete"} or not uid.isdigit(): return
        if action == "restart":
            result = await self._call("account_restart", {"uid": uid})
            text = f"أُرسل طلب إعادة تشغيل الحساب {uid}." if result.get("status") == "ok" else self._api_error(result, "تعذرت إعادة التشغيل.")
        else:
            result = await self._call("account_delete", {"uid": uid, "auth_uid": ""})
            text = f"تم حذف الحساب {uid}." if result.get("status") == "ok" else self._api_error(result, "تعذر حذف الحساب.")
        await self._send(chat_id, text, self._menu_keyboard())

    async def _confirm_global(self, chat_id: str, data: str) -> None:
        action = data.split(":", 1)[1]
        if action in {"pause_all", "resume_all"}:
            result = await self._call("pause_all", {})
            ok = result.get("status") == "ok"
            text = ("تم إيقاف جميع الحسابات مؤقتًا." if result.get("all_paused") else "تم استئناف جميع الحسابات.") if ok else "تعذر تغيير حالة الحسابات."
            await self._send(chat_id, text, self._menu_keyboard())
        elif action == "clear_logs":
            result = await self._call("clear_logs", {})
            await self._send(chat_id, "تم مسح سجلات التشغيل الحالية." if result.get("status") == "ok" else "تعذر مسح السجلات.", self._menu_keyboard())
        elif action == "cycle_start":
            result = await self._call("cycle_start", {})
            await self._send(chat_id, "بدأت دورة Battle Royale." if result.get("ok") else self._api_error(result, "تعذر بدء الدورة."), self._menu_keyboard())
        elif action == "cycle_stop":
            result = await self._call("cycle_stop", {})
            await self._send(chat_id, "أُرسل طلب إيقاف الدورة؛ يمكن للمباريات الحالية أن تنتهي دون بدء جولة جديدة." if result.get("ok") else self._api_error(result, "تعذر إيقاف الدورة."), self._menu_keyboard())

    async def _show_accounts(self, chat_id: str, page: int) -> None:
        data = await self._call("stats", {})
        accounts = data.get("accounts") if isinstance(data.get("accounts"), list) else []
        accounts = sorted(accounts, key=lambda a: str(a.get("uid", "")))
        total_pages = max(1, (len(accounts) + _ACCOUNT_PAGE_SIZE - 1) // _ACCOUNT_PAGE_SIZE)
        page = min(max(0, page), total_pages - 1)
        start = page * _ACCOUNT_PAGE_SIZE
        subset = accounts[start:start + _ACCOUNT_PAGE_SIZE]
        online = sum(1 for a in accounts if str(a.get("status", "")).upper() in {"ONLINE", "SEARCHING", "CONNECTING", "SERVER_RESPONDING", "ENTRY_UNCONFIRMED", "IN_MATCH_CONFIRMED"} and not a.get("is_paused"))
        lines = [f"الحسابات: {len(accounts)} · متصلة/نشطة: {online} · صفحة {page + 1}/{total_pages}"]
        rows = []
        for account in subset:
            uid = str(account.get("uid", ""))
            if not uid.isdigit(): continue
            status = str(account.get("status", "UNKNOWN"))[:32]
            nick = str(account.get("nickname", "—"))[:40]
            if account.get("is_paused"): status = "PAUSED"
            lines.append(f"\n{nick} · UID {uid}\nالحالة: {status} · المنطقة: {str(account.get('region', '—'))[:8]} · Reconnect: {int(account.get('reconnect_attempts') or 0)}")
            pause_action = "resume" if account.get("is_paused") or status == "PAUSED" else "pause"
            rows.extend([
                [{"text": "استئناف" if pause_action == "resume" else "إيقاف مؤقت", "callback_data": f"account:{pause_action}:{uid}"},
                 {"text": "إعادة تشغيل", "callback_data": f"account:restart:{uid}"}],
                [{"text": "تحديث الملف", "callback_data": f"account:refresh:{uid}"},
                 {"text": "حذف الحساب", "callback_data": f"account:delete:{uid}"}],
            ])
        nav = []
        if page > 0: nav.append({"text": "السابق", "callback_data": f"accounts:page:{page - 1}"})
        if page + 1 < total_pages: nav.append({"text": "التالي", "callback_data": f"accounts:page:{page + 1}"})
        if nav: rows.append(nav)
        rows.append([{"text": "تحديث", "callback_data": "menu:accounts"}, {"text": "القائمة", "callback_data": "menu:home"}])
        if not accounts: lines.append("لا توجد حسابات نشطة في الذاكرة حاليًا.")
        await self._send(chat_id, "".join(lines)[:3900], {"inline_keyboard": rows})

    async def _show_teams(self, chat_id: str) -> None:
        data = await self._call("teams", {})
        teams = data.get("teams") if isinstance(data.get("teams"), list) else []
        lines = [f"الفرق المسجلة: {len(teams)}"]
        for team in teams[:20]:
            members = team.get("members") if isinstance(team.get("members"), list) else []
            lines.append(f"\nالمنطقة {team.get('region') or '—'} · Clan {team.get('clan_id') or '—'} · الحالة {team.get('status') or '—'} · {len(members)} عضو")
            for member in members[:4]:
                lines.append(f"  UID {member.get('uid') or '—'} · {member.get('status') or '—'} · Clan: {member.get('clan_status') or 'unknown'} · Reconnect: {member.get('reconnect_attempts') or 0}")
        if not teams: lines.append("لا توجد فرق محفوظة.")
        await self._send(chat_id, "\n".join(lines)[:3900], {"inline_keyboard": [[
            {"text": "تحديث", "callback_data": "menu:teams"}, {"text": "إنشاء فريق", "callback_data": "menu:create"},
            {"text": "القائمة", "callback_data": "menu:home"},
        ]]})

    async def _show_cycle(self, chat_id: str) -> None:
        data = await self._call("cycle_status", {})
        groups = data.get("groups") if isinstance(data.get("groups"), list) else []
        lines = [f"دورة Battle Royale: {'نشطة' if data.get('active') else 'متوقفة'} · الجولة: {data.get('round') or 0} · الفرق: {len(groups)}"]
        for group in groups[:20]:
            lines.append(f"\nالفريق {group.get('id') or '—'} · {group.get('region') or '—'} · Clan {group.get('clan_id') or '—'}\nالحالة: {group.get('status') or '—'} · الجولة {group.get('round') or 0}")
            if group.get("last_error"): lines.append(f"آخر خطأ: {str(group['last_error'])[:160]}")
        if not groups: lines.append("لا توجد فرق في الدورة حاليًا.")
        rows = []
        if data.get("active"):
            rows.append([{"text": "إيقاف الدورة", "callback_data": "menu:cycle_stop"}])
        else:
            rows.append([{"text": "بدء Battle Royale", "callback_data": "menu:cycle_start"}])
        rows.append([{"text": "تحديث", "callback_data": "menu:cycle"}, {"text": "القائمة", "callback_data": "menu:home"}])
        await self._send(chat_id, "\n".join(lines)[:3900], {"inline_keyboard": rows})

    @staticmethod
    def _redact_log(text: str) -> str:
        value = str(text)
        value = re.sub(r"(?i)\b(password|passwd|auth_token|access_token|token|authorization|secret)(?:\s*[:=]\s*|\s+)\S+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)\bTOKEN\b.*$", "TOKEN [REDACTED]", value)
        value = re.sub(r"\b[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b", "[REDACTED_JWT]", value)
        value = re.sub(r"\b\d{5,}:[A-Za-z0-9_-]{20,}\b", "[REDACTED_BOT_TOKEN]", value)
        return value[:220]

    async def _show_logs(self, chat_id: str) -> None:
        data = await self._call("stats", {})
        logs = data.get("logs") if isinstance(data.get("logs"), list) else []
        lines = ["آخر سجلات التشغيل:"]
        for item in logs[-18:]:
            if not isinstance(item, dict): continue
            lines.append(f"[{str(item.get('time', ''))[:24]}] {self._redact_log(item.get('message', ''))}")
        if not logs: lines.append("لا توجد سجلات حاليًا.")
        await self._send(chat_id, "\n".join(lines)[:3900], {"inline_keyboard": [
            [{"text": "تحديث", "callback_data": "menu:logs"}, {"text": "مسح السجلات", "callback_data": "menu:clear_logs"}],
            [{"text": "القائمة", "callback_data": "menu:home"}],
        ]})

    @staticmethod
    def _menu_keyboard() -> dict[str, Any]:
        return {"inline_keyboard": [
            [{"text": "الحسابات", "callback_data": "menu:accounts"}, {"text": "الفرق", "callback_data": "menu:teams"}],
            [{"text": "دورة Battle Royale", "callback_data": "menu:cycle"}, {"text": "السجلات", "callback_data": "menu:logs"}],
            [{"text": "إنشاء فريق", "callback_data": "menu:create"}, {"text": "إيقاف/استئناف الكل", "callback_data": "menu:pause_all"}],
        ]}

    async def _send(self, chat_id: str, text: str, keyboard: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:3900], "disable_web_page_preview": True}
        if keyboard: payload["reply_markup"] = keyboard
        started = time.monotonic()
        try:
            await self._telegram("sendMessage", payload)
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            _LOG.error("Telegram sendMessage failed (%s, elapsed_ms=%s)", type(exc).__name__, elapsed_ms)

    async def _answer_callback(self, callback_id: Any, text: str = "", alert: bool = False) -> None:
        if not callback_id: return
        try:
            payload: dict[str, Any] = {"callback_query_id": str(callback_id)}
            if text: payload["text"] = text[:180]
            if alert: payload["show_alert"] = True
            started = time.monotonic()
            await self._telegram("answerCallbackQuery", payload)
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            _LOG.warning("Telegram callback acknowledgement failed (%s, elapsed_ms=%s)", type(exc).__name__, elapsed_ms)
