import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import state_store
from telegram_bot import TelegramBot


class MemoryStore:
    def __init__(self):
        self.ids = set()

    def claim_telegram_update(self, update_id):
        if update_id in self.ids:
            return False
        self.ids.add(update_id)
        return True


class TelegramBotTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "test-token-not-real",
            "TELEGRAM_WEBHOOK_SECRET": "local-test-secret_123",
            "TELEGRAM_WEBHOOK_URL": "https://example.invalid/telegram/webhook",
            "TELEGRAM_ALLOWED_USER_IDS": "100000001,100000002,100000003",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.bot = TelegramBot({}, MemoryStore())
        self.bot._telegram = AsyncMock(return_value={"ok": True, "result": {}})

    async def test_only_allowlisted_private_chat_ids_are_authorized(self):
        for user_id in ("100000001", "100000002", "100000003"):
            self.assertTrue(self.bot._is_private_owner(user_id, {"id": int(user_id), "type": "private"}))
        self.assertFalse(self.bot._is_private_owner("199999999", {"id": 199999999, "type": "private"}))
        self.assertFalse(self.bot._is_private_owner("100000001", {"id": -100, "type": "supergroup"}))
        self.assertFalse(self.bot._is_private_owner("100000001", {"id": 100000002, "type": "private"}))

    async def test_start_command_returns_menu_without_echoing_input(self):
        await self.bot._handle_message({
            "from": {"id": 100000001},
            "chat": {"id": 100000001, "type": "private"},
            "text": "/start",
        })
        self.bot._telegram.assert_awaited_once()
        args, _kwargs = self.bot._telegram.await_args
        self.assertEqual(args[0], "sendMessage")
        sent = args[1]
        self.assertIn("AlZ3By", sent["text"])
        self.assertIn("inline_keyboard", sent["reply_markup"])

    async def test_untrusted_and_group_messages_produce_no_bot_replies(self):
        await self.bot._handle_message({
            "from": {"id": 199999999}, "chat": {"id": 199999999, "type": "private"}, "text": "/start"
        })
        await self.bot._handle_message({
            "from": {"id": 100000001}, "chat": {"id": -100, "type": "supergroup"}, "text": "/start"
        })
        self.bot._telegram.assert_not_awaited()

    async def test_webhook_secret_and_update_deduplication(self):
        payload = json.dumps({"update_id": 42, "message": {
            "from": {"id": 100000001},
            "chat": {"id": 100000001, "type": "private"},
            "text": "/start",
        }}).encode()
        request = SimpleNamespace(
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
            content_length=len(payload), read=AsyncMock(return_value=payload),
        )
        rejected = await self.bot.webhook(request)
        self.assertEqual(rejected.status, 403)

        request.headers["X-Telegram-Bot-Api-Secret-Token"] = "local-test-secret_123"
        first = await self.bot.webhook(request)
        second = await self.bot.webhook(request)
        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertEqual(json.loads(second.text)["duplicate"], True)
        self.assertEqual(self.bot._telegram.await_count, 1)

    async def test_startup_registers_https_webhook_without_real_network(self):
        await self.bot.startup()
        first_call = self.bot._telegram.await_args_list[0]
        self.assertEqual(first_call.args[0], "setWebhook")
        self.assertEqual(first_call.args[1]["url"], "https://example.invalid/telegram/webhook")
        self.assertEqual(first_call.args[1]["secret_token"], "local-test-secret_123")
        self.assertTrue(self.bot._started)
        await self.bot.close()

    async def test_state_store_claims_local_update_once(self):
        with state_store._LOCK:
            state_store._LOCAL_TELEGRAM_UPDATES.clear()
            state_store._LOCAL_TELEGRAM_UPDATE_ORDER.clear()
        with patch.object(state_store, "database_configured", return_value=False):
            self.assertTrue(state_store.claim_telegram_update(808080))
            self.assertFalse(state_store.claim_telegram_update(808080))

    async def test_api_delegation_uses_existing_handler_and_payload(self):
        response = SimpleNamespace(status=200, text='{"status":"ok","is_paused":true}')
        handler = AsyncMock(return_value=response)
        self.bot.actions["account_pause"] = handler
        result = await self.bot._call("account_pause", {"uid": "123456"})
        self.assertEqual(result["status"], "ok")
        request = handler.await_args.args[0]
        self.assertEqual(await request.json(), {"uid": "123456"})

    async def test_team_creation_confirmation_calls_shared_api_with_server_default(self):
        response = SimpleNamespace(status=200, text='{"ok":true,"msg":"creating 4 bots"}')
        handler = AsyncMock(return_value=response)
        self.bot.actions["create_team"] = handler
        self.bot._flows["100000001"] = {
            "step": "confirm_team", "region": "ME", "clan_id": "3106587789", "count": 4
        }
        await self.bot._handle_callback({
            "id": "cb1", "from": {"id": 100000001},
            "message": {"chat": {"id": 100000001, "type": "private"}},
            "data": "create:confirm",
        })
        request = handler.await_args.args[0]
        payload = await request.json()
        self.assertEqual(payload, {
            "region": "ME", "clan_id": "3106587789", "count": 4, "password": "AlZ3By"
        })
        self.assertNotIn("100000001", json.dumps(payload))

    async def test_log_redaction(self):
        redacted = self.bot._redact_log("TOKEN Login 12345678901234567890 secret=password123")
        self.assertNotIn("12345678901234567890", redacted)
        self.assertNotIn("password123", redacted)


if __name__ == "__main__":
    unittest.main()
