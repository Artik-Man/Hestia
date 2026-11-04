"""Regression tests for the controlled A-only expiry experiment."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dns.message
from cache import WinnerCache
from fixture import answer
from fixture import ask as fixture_ask


class CacheTests(unittest.IsolatedAsyncioTestCase):
    """Exercise fresh selection, eligibility and concurrent refresh without a live DNS server."""

    async def asyncSetUp(self):
        """Provide a private availability marker and a standard IN/A question."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.down = Path(temporary.name) / "fi-down"
        self.q = dns.message.make_query("example.lab.test.", "A")

    async def test_coalesced_renewal_and_zero_ttl(self):
        """Two waiting flows reuse one upstream wave, and a zero-TTL result expires immediately."""
        calls = []
        entered = asyncio.Event()
        release = asyncio.Event()

        async def ask(query, addr, port=53, group=None):
            """Hold both upstreams until two callers are pending, then return uncached data."""
            calls.append(group)
            if len(calls) == 2:
                entered.set()
            await release.wait()
            return answer(query, "203.0.113.11", ttl=0)

        with mock.patch("cache.ask", ask):
            cache = WinnerCache(self.down)
            pair = asyncio.gather(cache.select(self.q), cache.select(self.q))
            await asyncio.wait_for(entered.wait(), 1)
            release.set()
            first, second = await pair
            self.assertEqual(first, second)
            self.assertEqual(first.remaining(), 0)
            self.assertCountEqual(calls, ["ru", "fi"])
            await cache.select(self.q)
            self.assertCountEqual(calls, ["ru", "fi", "ru", "fi"])

    async def test_recheck_down_before_serving(self):
        """A cached FI address and a pending FI reply become ineligible when the explicit group is down."""
        q = dns.message.make_query("only-fi.lab.test.", "A")
        entered = asyncio.Event()
        release = asyncio.Event()

        async def ask(query, addr, port=53, group=None):
            """Simulate a pending positive FI answer across a change of availability."""
            self.assertEqual(group, "fi")
            entered.set()
            await release.wait()
            return answer(query, "203.0.113.11", ttl=30)

        with mock.patch("cache.ask", ask):
            cache = WinnerCache(self.down)
            task = asyncio.create_task(cache.select(q))
            await asyncio.wait_for(entered.wait(), 1)
            self.down.touch()
            release.set()
            self.assertIsNone(await task)
            self.down.unlink()
            self.assertIsNotNone(await cache.select(q))
            self.down.touch()
            self.assertIsNone(await cache.select(q))

    async def test_expired_winner_rotates_once_and_late_response_cannot_overwrite(self):
        """Reuse .11 until exact expiry, then renew concurrent flows once and keep .22 despite an older late reply."""
        delayed = asyncio.Event()
        first_ru_started = asyncio.Event()
        calls = {"ru": 0, "fi": 0}
        now = [100.0]

        async def ask(query, addr, port=53, group=None):
            """Emit a delayed old candidate after the second upstream wave has already selected .22."""
            calls[group] += 1
            if calls[group] == 1 and group == "ru":
                first_ru_started.set()
                await delayed.wait()
                return answer(query, "203.0.113.33", ttl=45)
            if group == "fi" and calls[group] == 1:
                await first_ru_started.wait()
                return answer(query, "203.0.113.11", ttl=2)
            if group == "ru":
                return answer(query, "203.0.113.22", ttl=10)
            return answer(query, code=3)

        with (
            mock.patch("cache.ask", ask),
            mock.patch("cache.monotonic", lambda: now[0]),
        ):
            cache = WinnerCache(self.down)
            old = await cache.select(self.q)
            self.assertEqual(old.ip, "203.0.113.11")
            now[0] = 101.75
            self.assertEqual(await cache.select(self.q), old)
            self.assertEqual(old.remaining(), 0)
            self.assertEqual(calls, {"fi": 1, "ru": 1})
            now[0] = 102.0
            first, second = await asyncio.gather(
                cache.select(self.q), cache.select(self.q)
            )
            self.assertEqual(first, second)
            self.assertEqual(
                (first.group, first.ip, first.remaining()), ("ru", "203.0.113.22", 10)
            )
            delayed.set()
            await asyncio.gather(*cache.pending)
            self.assertEqual(await cache.select(self.q), first)
            self.assertEqual(calls, {"fi": 2, "ru": 2})

    async def test_untrusted_response_origin_and_id(self):
        """Reject a reply from a different socket or DNS transaction, also under python -O."""
        loop = asyncio.get_running_loop()
        address, port = "127.0.0.1", 1053
        for wrong in ("origin", "transaction"):
            with self.subTest(wrong=wrong):
                reply = answer(self.q, "203.0.113.11")
                if wrong == "transaction":
                    reply.id = (self.q.id + 1) % 65536
                sender = (address, port + 1) if wrong == "origin" else (address, port)
                with (
                    mock.patch.object(loop, "sock_sendto", new_callable=mock.AsyncMock),
                    mock.patch.object(
                        loop,
                        "sock_recvfrom",
                        new_callable=mock.AsyncMock,
                        return_value=(reply.to_wire(), sender),
                    ),
                    self.assertRaises(OSError),
                ):
                    await fixture_ask(self.q, address, port)

    async def test_down_before_dispatch(self):
        """Deny an FI lookup selected earlier if the group was disabled before its task first executes."""
        self.down.touch()
        q = dns.message.make_query("only-fi.lab.test.", "A")
        cache = WinnerCache(self.down)
        with mock.patch("cache.ask", new_callable=mock.AsyncMock) as send:
            selected = await cache.refresh(q, ("fi",))
            send.assert_not_awaited()
            self.assertIsNone(selected)
