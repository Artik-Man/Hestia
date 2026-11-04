"""Controlled-clock checks of DNS warming separate from on-wire ARM64 acceptance."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dns.message
from cache import Config, History, WarmCache, rotation


class HistoryTests(unittest.TestCase):
    """Count and schedule only genuine recent demand with a hard bound on retained names."""

    def test_exact_window_retransmits_and_rare_names(self):
        """One transaction counts once, and the oldest visit expires exactly at X without help from the background."""
        history = History(Config(3, 5, 1), capacity=2)
        key = "site.test", "A"
        for times, token in [((0, 0.1), 10), ((1,), 11), ((2,), 12)]:
            for t in times:
                history.record(key, ("127.0.0.1", 1234, token), t)
        self.assertEqual(history.count(key, 4.99), 3)
        self.assertEqual(history.count(key, 5), 2)
        history.prune(7)
        self.assertNotIn(key, history.entries)
        history.record(key, ("127.0.0.1", 1234, 13), 7.1)
        self.assertEqual(history.count(key, 7.1), 1)

    def test_capacity_never_promotes_singles(self):
        """An evicted rare domain needs N new client transactions to become eligible."""
        history = History(Config(2, 5, 1), capacity=2)
        for n in range(20):
            history.record((str(n), "A"), ("peer", 1234, n), n / 100)
        self.assertLessEqual(len(history.entries), 2)
        history.record(("0", "A"), ("peer", 1234, 21), 0.3)
        self.assertEqual(history.count(("0", "A"), 0.3), 1)


class WarmTests(unittest.IsolatedAsyncioTestCase):
    """Test the boundary between successful refresh, delivery TTL and recent client demand."""

    async def test_zero_ttl_never_schedules(self):
        """A TTL-zero source is known but cannot enter the refresh queue."""
        now = [10.0]
        cache = WarmCache(
            Path("/unavailable-fi-test-marker"), Config(2, 5, 1), clock=lambda: now[0]
        )
        key = ("only-fi.lab.test", "A")
        cache.history.record(key, ("peer", 1, 1), now[0])
        cache.history.record(key, ("peer", 1, 2), now[0])
        cache.remember(key, rotation.Winner("fi", "203.0.113.11", now[0]), now[0])
        now[0] += 0.9
        cache.tick()
        self.assertFalse(cache.jobs)
        self.assertEqual(cache.history.count(key, now[0]), 2)

    async def test_failure_keeps_original_expiry_and_lookup_does_not_count(self):
        """Refresh failure preserves a live winner without extending it. Attempts cease once N expires."""
        now = [10.0]
        with tempfile.TemporaryDirectory() as temp:
            cache = WarmCache(
                Path(temp) / "down", Config(2, 3, 1), clock=lambda: now[0]
            )
            q = dns.message.make_query("only-fi.lab.test", "A")
            key = ("only-fi.lab.test", "A")
            calls = []

            async def resolver(query, group):
                """Provide one usable winner and then simulate transient resolution failures."""
                calls.append(group)
                return (
                    rotation.Winner("fi", "203.0.113.11", 14.0)
                    if len(calls) == 1
                    else None
                )

            with (
                mock.patch.object(rotation.WinnerCache, "lookup", side_effect=resolver),
                mock.patch.object(rotation, "monotonic", lambda: now[0]),
            ):
                q.id = 1
                await cache.client_select(q, ("127.0.0.1", 1234))
                now[0] = 10.2
                q.id = 2
                await cache.client_select(q, ("127.0.0.1", 1234))
                now[0] = 11.25
                cache.tick()
                await asyncio.gather(*cache.jobs.values())
                self.assertEqual(calls, ["fi", "fi"])
                winner = await cache.select(q)
                self.assertEqual(winner.expires, 14.0)
                self.assertEqual(cache.history.count(key, now[0]), 2)
                now[0] = 13.0
                cache.tick()
                self.assertFalse(cache.jobs)
                self.assertEqual(cache.history.count(key, now[0]), 1)
                now[0] = 14.0
                self.assertIsNone(await cache.select(q))
                cache.tick()
                self.assertFalse(cache.jobs)
                self.assertNotIn(key, cache.history.entries)
                self.assertEqual(calls, ["fi", "fi", "fi"])

    async def test_flow_joins_background_and_rechecks_policy(self):
        """An expired foreground request joins the same eligible upstream job without inserting a visit."""
        now = [10.0]
        entered, release = asyncio.Event(), asyncio.Event()
        with tempfile.TemporaryDirectory() as temp:
            down = Path(temp) / "down"
            cache = WarmCache(down, Config(2, 5, 1), clock=lambda: now[0])
            key = ("only-fi.lab.test", "A")
            cache.history.record(key, ("peer", 1, 1), now[0])
            cache.history.record(key, ("peer", 1, 2), now[0])
            cache.remember(key, rotation.Winner("fi", "203.0.113.11", 11.0), now[0])

            async def resolver(query, group):
                """Hold the single shared refresh until its route becomes administratively forbidden."""
                entered.set()
                await release.wait()
                return rotation.Winner("fi", "203.0.113.22", 15.0)

            with mock.patch.object(
                rotation.WinnerCache, "lookup", side_effect=resolver
            ) as send:
                now[0] = 11
                cache.tick()
                await asyncio.wait_for(entered.wait(), 1)
                flow = asyncio.create_task(
                    cache.select(dns.message.make_query(key[0], "A"))
                )
                while not cache.inflight:
                    await asyncio.sleep(0)
                down.touch()
                release.set()
                self.assertIsNone(await flow)
                await asyncio.gather(*cache.jobs.values())
                self.assertEqual(send.await_count, 1)
                self.assertEqual(cache.history.count(key, 11), 2)
                self.assertFalse(cache.winners)

    async def test_eligible_alternate_can_reuse_its_own_positive(self):
        """Reuse the permitted RU candidate while FI is disabled, never extending either original TTL."""
        now = [10.0]
        with tempfile.TemporaryDirectory() as temp:
            down = Path(temp) / "down"
            cache = WarmCache(down, Config(2, 5, 1), clock=lambda: now[0])
            key = ("hot.lab.test", "A")
            query = dns.message.make_query(key[0], "A")
            cache.history.record(key, ("peer", 1, 1), 10.0)
            fi = rotation.Winner("fi", "203.0.113.11", 14.0)
            ru = rotation.Winner("ru", "203.0.113.22", 12.0)
            cache.remember(key, fi, 10)
            cache.remember(key, ru, 10)
            cache.winners[key[0], ("ru", "fi")] = fi
            with (
                mock.patch.object(rotation, "monotonic", lambda: now[0]),
                mock.patch.object(
                    rotation.WinnerCache, "lookup", return_value=None
                ) as send,
            ):
                self.assertEqual(await cache.select(query), fi)
                down.touch()
                self.assertEqual(await cache.select(query), ru)
                send.assert_not_awaited()
                now[0] = 12.0
                self.assertIsNone(await cache.select(query))
                send.assert_awaited_once_with(query, "ru")
                self.assertEqual(cache.history.count(key, now[0]), 1)

    async def test_nonqueries_do_not_count_or_resolve(self):
        """An inbound DNS response is dropped and a foreign opcode is rejected before tracking or arbitration."""
        cache = WarmCache(Path("/unused-fi-marker"), Config(2, 5, 1))
        q = dns.message.make_query("invalid.lab.test", "A")
        unsupported = dns.message.make_query("invalid.lab.test", "A")
        unsupported.set_opcode(dns.opcode.STATUS)
        handlers = {}
        ready = asyncio.Event()

        async def bind(addr, port, callback):
            """Capture the real gateway listener callback without opening a socket."""
            handlers[port] = callback
            if port == 1055:
                ready.set()
            return mock.Mock(), None

        with (
            mock.patch.object(rotation, "bind", side_effect=bind),
            mock.patch.object(
                cache, "select", new_callable=mock.AsyncMock, return_value=None
            ) as resolve,
        ):
            gateway = asyncio.create_task(
                rotation.gateway(cache.down, cache, cache.client_select)
            )
            try:
                await asyncio.wait_for(ready.wait(), 1)
                dropped = await handlers[53](
                    dns.message.make_response(q).to_wire(), ("peer", 1234)
                )
                refused = await handlers[53](unsupported.to_wire(), ("peer", 1234))
                self.assertIsNone(dropped)
                self.assertEqual(
                    dns.message.from_wire(refused).rcode(), dns.rcode.NOTIMP
                )
                self.assertFalse(cache.history.entries)
                resolve.assert_not_awaited()
            finally:
                gateway.cancel()
                await asyncio.gather(gateway, return_exceptions=True)

    async def test_boundary_between_enqueue_and_child_send(self):
        """At exact X a previously queued warm task must refrain from sending; foreground still renews."""
        now = [10.0]
        key = ("only-fi.lab.test", "A")
        with tempfile.TemporaryDirectory() as temp:
            cache = WarmCache(
                Path(temp) / "down", Config(2, 3, 1), clock=lambda: now[0]
            )
            cache.history.record(key, ("peer", 1, 1), 10)
            cache.history.record(key, ("peer", 1, 2), 10.5)
            cache.remember(key, rotation.Winner("fi", "203.0.113.11", 11.0), now[0])
            value = rotation.Winner("fi", "203.0.113.22", 20)
            with (
                mock.patch.object(
                    rotation.WinnerCache, "lookup", return_value=value
                ) as send,
                mock.patch.object(rotation, "monotonic", lambda: now[0]),
            ):
                now[0] = 12.9
                job = asyncio.create_task(cache.refresh_source(key, "fi"))
                await asyncio.sleep(0)
                self.assertTrue(cache.channels)
                now[0] = 13.0
                await job
                send.assert_not_awaited()
                self.assertEqual(
                    await cache.select(dns.message.make_query(key[0], "A")), value
                )
                self.assertEqual(send.await_count, 1)
                self.assertEqual(cache.history.count(key, now[0]), 1)

    async def test_same_source_refresh_updates_older_eligible_views(self):
        """After re-entering an earlier allowed set, use the newest answer of that source until its own TTL."""
        now = [10.0]
        key = ("split.lab.test", "A")
        query = dns.message.make_query(key[0], "A")
        with tempfile.TemporaryDirectory() as temp:
            down = Path(temp) / "down"
            cache = WarmCache(down, Config(2, 10, 1), clock=lambda: now[0])
            cache.history.record(key, ("peer", 1, 1), 10)
            cache.history.record(key, ("peer", 1, 2), 10)
            fi = rotation.Winner("fi", "203.0.113.22", 20)
            old_ru = rotation.Winner("ru", "203.0.113.11", 40)
            new_ru = rotation.Winner("ru", "203.0.113.33", 13)
            cache.remember(key, fi, 10)
            cache.remember(key, old_ru, 10)
            cache.winners[key[0], ("ru", "fi")] = fi
            cache.winners[key[0], ("ru",)] = old_ru
            now[0] = 11.5
            with (
                mock.patch.object(rotation, "monotonic", lambda: now[0]),
                mock.patch.object(
                    rotation.WinnerCache, "lookup", side_effect=[new_ru, None]
                ) as upstream,
            ):
                await cache.refresh_source(key, "ru")
                self.assertEqual(await cache.select(query), fi)
                down.touch()
                self.assertEqual(await cache.select(query), new_ru)
                self.assertEqual(upstream.await_count, 1)
                now[0] = 13
                self.assertIsNone(await cache.select(query))
                self.assertEqual(upstream.await_args.args[1], "ru")
                self.assertEqual(upstream.await_count, 2)

    async def test_winner_revoked_while_fakeip_is_issued(self):
        """The actual LAN listener refuses its pending FI answer, then reuses eligible RU for a committed flow."""
        key = ("split.lab.test", "A")
        q = dns.message.make_query(key[0], "A")
        handlers = {}
        ready = asyncio.Event()

        async def bind(addr, port, callback):
            """Capture the real gateway listener callbacks for a controlled dispatch."""
            handlers[port] = callback
            if port == 1055:
                ready.set()
            return mock.Mock(), None

        with tempfile.TemporaryDirectory() as temp:
            down = Path(temp) / "down"
            cache = WarmCache(down, Config(2, 10, 1), clock=lambda: 10.0)
            cache.history.record(key, ("peer", 1, 1), 10)
            fi = rotation.Winner("fi", "203.0.113.22", 20)
            ru = rotation.Winner("ru", "203.0.113.11", 14)
            cache.remember(key, fi, 10)
            cache.remember(key, ru, 10)
            cache.winners[key[0], ("ru", "fi")] = fi

            async def issuer(query, addr, port):
                """Change FI eligibility after a candidate was chosen, before encoding the FakeIP reply."""
                self.assertEqual((addr, port), ("127.0.0.1", 1054))
                down.touch()
                return rotation.answer(query, "198.18.0.1")

            with (
                mock.patch.object(rotation, "monotonic", lambda: 10.0),
                mock.patch.object(rotation, "bind", side_effect=bind),
                mock.patch.object(rotation, "ask", side_effect=issuer),
                mock.patch.object(
                    rotation.WinnerCache, "lookup", new_callable=mock.AsyncMock
                ) as send,
            ):
                service = asyncio.create_task(
                    rotation.gateway(down, cache, cache.client_select)
                )
                try:
                    await asyncio.wait_for(ready.wait(), 1)
                    lan = dns.message.from_wire(
                        await handlers[53](q.to_wire(), ("peer", 1234))
                    )
                    self.assertEqual(lan.rcode(), dns.rcode.SERVFAIL)
                    self.assertFalse(lan.answer)
                    flow = dns.message.from_wire(
                        await handlers[1055](q.to_wire(), ("local", 1234))
                    )
                    self.assertEqual(rotation.unpack(flow), ru.ip)
                    self.assertEqual(flow.answer[0].ttl, 4)
                    send.assert_not_awaited()
                finally:
                    service.cancel()
                    await asyncio.gather(service, return_exceptions=True)
