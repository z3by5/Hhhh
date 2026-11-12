import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import main


class CreateAccountsApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_creating = main.bot_state.creating
        main.bot_state.creating = False

    async def asyncTearDown(self):
        main.bot_state.creating = self.original_creating

    async def _request(self, payload):
        return SimpleNamespace(json=AsyncMock(return_value=payload))

    async def test_rejects_out_of_range_quantity_and_invalid_region(self):
        for count in (0, 101, True, "3"):
            response = await main.api_create_accounts(await self._request({"region": "ME", "count": count}))
            self.assertEqual(response.status, 400)
        response = await main.api_create_accounts(await self._request({"region": "UNKNOWN", "count": 1}))
        self.assertEqual(response.status, 400)
        self.assertFalse(main.bot_state.creating)

    async def test_starts_standalone_batch_using_existing_generator(self):
        finished = asyncio.Event()

        async def fake_create(region, clan_id, count, password):
            self.assertEqual((region, clan_id, count, password), ("ME", "", 3, "AlZ3By"))
            finished.set()
            return []

        with patch.object(main, "create_four_accounts", new=AsyncMock(side_effect=fake_create)) as create:
            response = await main.api_create_accounts(await self._request({"region": "ME", "count": 3}))
            self.assertEqual(response.status, 200)
            self.assertTrue(main.bot_state.creating)
            await asyncio.wait_for(finished.wait(), timeout=1)
            await asyncio.sleep(0)
            create.assert_awaited_once_with("ME", "", 3, "AlZ3By")
        main.bot_state.creating = False

    async def test_refuses_parallel_creation(self):
        main.bot_state.creating = True
        response = await main.api_create_accounts(await self._request({"region": "ME", "count": 1}))
        self.assertEqual(response.status, 409)

    async def test_accepts_maximum_batch_of_100(self):
        finished = asyncio.Event()

        async def fake_create(region, clan_id, count, password):
            self.assertEqual((region, clan_id, count, password), ("ME", "", 100, "AlZ3By"))
            finished.set()
            return []

        with patch.object(main, "create_four_accounts", new=AsyncMock(side_effect=fake_create)) as create:
            response = await main.api_create_accounts(await self._request({"region": "ME", "count": 100}))
            self.assertEqual(response.status, 200)
            await asyncio.wait_for(finished.wait(), timeout=1)
            create.assert_awaited_once_with("ME", "", 100, "AlZ3By")
        main.bot_state.creating = False


if __name__ == "__main__":
    unittest.main()
