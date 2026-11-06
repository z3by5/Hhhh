import time
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives.asymmetric import rsa

from telegram_auth import (
    ISSUER,
    SESSION_COOKIE,
    TX_COOKIE,
    TelegramAuth,
    TelegramAuthError,
)


BASE_ENV = {
    "TELEGRAM_CLIENT_ID": "123456789",
    "TELEGRAM_CLIENT_SECRET": "test-client-secret-not-real",
    "TELEGRAM_REDIRECT_URI": "https://hhhh-2-7k5d.onrender.com/auth/telegram/callback",
    "TELEGRAM_SESSION_SECRET": "local-test-session-secret-32-bytes-long",
    "TELEGRAM_ALLOWED_USER_IDS": "987654321",
}


class TelegramAuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", BASE_ENV, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.auth = TelegramAuth()

    async def test_oidc_start_and_callback_create_allowlisted_session(self):
        start_request = make_mocked_request("GET", "/auth/telegram/start")
        start_response = await self.auth.start(start_request)
        self.assertEqual(start_response.status, 302)
        authorization = urlsplit(start_response.headers["Location"])
        params = parse_qs(authorization.query)
        self.assertEqual(authorization.netloc, "oauth.telegram.org")
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["redirect_uri"], [BASE_ENV["TELEGRAM_REDIRECT_URI"]])

        transaction_cookie = start_response.cookies[TX_COOKIE].value
        state = params["state"][0]
        callback_request = make_mocked_request(
            "GET", f"/auth/telegram/callback?code=mock-code&state={state}",
            headers={"Cookie": f"{TX_COOKIE}={transaction_cookie}"},
        )
        self.auth._exchange_code = AsyncMock(return_value={"id_token": "test-id-token"})
        self.auth.validate_id_token = AsyncMock(return_value={
            "_telegram_user_id": "987654321",
            "preferred_username": "test_user",
            "name": "Test User",
        })

        callback_response = await self.auth.callback(callback_request)
        self.assertEqual(callback_response.status, 302)
        self.assertEqual(callback_response.headers["Location"], "/?auth=success")
        session_cookie = callback_response.cookies[SESSION_COOKIE].value
        session_request = make_mocked_request(
            "GET", "/api/session", headers={"Cookie": f"{SESSION_COOKIE}={session_cookie}"},
        )
        session = self.auth.get_session(session_request)
        self.assertEqual(session["id"], "987654321")
        self.assertEqual(session["username"], "test_user")

    async def test_callback_denies_id_not_in_allowlist(self):
        start_response = await self.auth.start(make_mocked_request("GET", "/auth/telegram/start"))
        params = parse_qs(urlsplit(start_response.headers["Location"]).query)
        transaction_cookie = start_response.cookies[TX_COOKIE].value
        request = make_mocked_request(
            "GET", f"/auth/telegram/callback?code=mock-code&state={params['state'][0]}",
            headers={"Cookie": f"{TX_COOKIE}={transaction_cookie}"},
        )
        self.auth._exchange_code = AsyncMock(return_value={"id_token": "test-id-token"})
        self.auth.validate_id_token = AsyncMock(return_value={"_telegram_user_id": "111222333"})
        response = await self.auth.callback(request)
        self.assertEqual(response.headers["Location"], "/?auth=denied")
        self.assertNotIn(SESSION_COOKIE, response.cookies)

    async def test_id_token_signature_issuer_audience_nonce_and_time_are_validated(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = private_key.public_key().public_numbers()

        def encode_uint(value):
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return TelegramAuth._b64u(raw)

        jwk = {
            "kty": "RSA", "kid": "local-test-key", "use": "sig", "alg": "RS256",
            "n": encode_uint(public_numbers.n), "e": encode_uint(public_numbers.e),
        }
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": BASE_ENV["TELEGRAM_CLIENT_ID"],
            "sub": "987654321",
            "id": 987654321,
            "iat": now,
            "exp": now + 300,
            "nonce": "expected-nonce",
        }
        encoded = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "local-test-key"})
        self.auth._fetch_jwks = AsyncMock(return_value=[jwk])
        validated = await self.auth.validate_id_token(encoded, self.auth._settings(), "expected-nonce")
        self.assertEqual(validated["_telegram_user_id"], "987654321")

        with self.assertRaises(TelegramAuthError):
            await self.auth.validate_id_token(encoded, self.auth._settings(), "wrong-nonce")

        bad_audience = dict(claims, aud="other-client")
        bad_token = jwt.encode(bad_audience, private_key, algorithm="RS256", headers={"kid": "local-test-key"})
        with self.assertRaises(TelegramAuthError):
            await self.auth.validate_id_token(bad_token, self.auth._settings(), "expected-nonce")

        expired_claims = dict(claims, exp=now - 60)
        expired_token = jwt.encode(expired_claims, private_key, algorithm="RS256", headers={"kid": "local-test-key"})
        with self.assertRaises(TelegramAuthError):
            await self.auth.validate_id_token(expired_token, self.auth._settings(), "expected-nonce")

        future_claims = dict(claims, iat=now + 120, exp=now + 300)
        future_token = jwt.encode(future_claims, private_key, algorithm="RS256", headers={"kid": "local-test-key"})
        with self.assertRaises(TelegramAuthError):
            await self.auth.validate_id_token(future_token, self.auth._settings(), "expected-nonce")

    async def test_tampered_or_expired_session_cookie_is_rejected(self):
        settings = self.auth._settings()
        payload = {"id": "987654321", "username": "test_user", "name": "Test User",
                   "iat": int(time.time()), "exp": int(time.time()) + 60}
        signed = self.auth._sign_payload(payload, settings["session_secret"], "session")
        tampered = signed[:-1] + ("A" if signed[-1] != "A" else "B")
        request = make_mocked_request("GET", "/api/session", headers={"Cookie": f"{SESSION_COOKIE}={tampered}"})
        self.assertIsNone(self.auth.get_session(request))
        expired_payload = dict(payload, exp=int(time.time()) - 1)
        expired = self.auth._sign_payload(expired_payload, settings["session_secret"], "session")
        request = make_mocked_request("GET", "/api/session", headers={"Cookie": f"{SESSION_COOKIE}={expired}"})
        self.assertIsNone(self.auth.get_session(request))

    async def test_login_is_disabled_without_allowlist_or_long_session_secret(self):
        with patch.dict("os.environ", {"TELEGRAM_ALLOWED_USER_IDS": "", "TELEGRAM_SESSION_SECRET": "short"}):
            self.assertFalse(self.auth._settings()["enabled"])


if __name__ == "__main__":
    unittest.main()
