"""Strict and opt-in stale policy tests using controlled monotonic time and resolver responses."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dns.edns
import dns.flags
import dns.message
import dns.rrset
from cache import StaleCache, rotation


class StaleTests(unittest.IsolatedAsyncioTestCase):
    """Refresh a known A through eligible groups and check the decision against its original expiry."""

    def setUp(self):
        """Install a private marker and a controlled clock/resolver without using the network."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.down = Path(temporary.name) / "down"
        self.now = 10.0
        self.query = dns.message.make_query("only-fi.lab.test", "A")
        self.reply = {"fi": "203.0.113.11", "ru": "timeout"}
        self.ttl = 2
        self.calls = []

        async def ask(q, addr, port=53, group=None):
            """Translate a controlled result into an exact DNS transaction for the querying source."""
            self.calls.append(group)
            mode = self.reply[group]
            if mode == "timeout":
                raise TimeoutError()
            if mode == "bad":
                raise OSError("unexpected sender")
            if mode in ("nodata", "nxdomain", "ambiguous"):
                result = rotation.answer(q, code=3 if mode == "nxdomain" else 0)
                if mode != "ambiguous":
                    result.flags |= dns.flags.AA
                return result
            if mode == "servfail":
                return rotation.answer(q, code=2)
            return rotation.answer(q, mode, ttl=self.ttl)

        patch = mock.patch("cache.ask", ask)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(rotation, "monotonic", lambda: self.now)
        patch.start()
        self.addCleanup(patch.stop)
        self.cache = StaleCache(self.down, 5, clock=lambda: self.now)

    async def test_boundary_negative_and_recovery(self):
        """Stale expires at the original deadline, replies do not renew it and freshness resumes on B."""
        self.assertEqual((await self.cache.select(self.query)).ip, "203.0.113.11")
        self.now = 12
        self.reply["fi"] = "timeout"
        old = await self.cache.select(self.query)
        self.assertEqual((old.ip, old.remaining()), ("203.0.113.11", 0))
        self.now = 16.99
        self.assertEqual((await self.cache.select(self.query)).expires, 12)
        self.now = 17
        self.assertFalse(self.cache.permits_answer(self.query, old))
        self.assertIsNone(await self.cache.select(self.query))
        self.reply["fi"] = "203.0.113.22"
        self.assertEqual((await self.cache.select(self.query)).ip, "203.0.113.22")

    async def test_definitive_negative_purges_original(self):
        """Actual NXDOMAIN and NODATA survive arbitration and prevent resurrection in a later outage."""
        for mode, code in (("nxdomain", 3), ("nodata", 0)):
            self.cache = StaleCache(self.down, 5, clock=lambda: self.now)
            self.reply["fi"] = "203.0.113.11"
            await self.cache.select(self.query)
            self.now += 2
            self.reply["fi"] = mode
            with self.assertRaises(rotation.NegativeAnswer) as caught:
                await self.cache.select(self.query)
            self.assertEqual(caught.exception.code, code)
            self.reply["fi"] = "servfail"
            self.assertIsNone(await self.cache.select(self.query))

    async def test_zero_ttl_ineligible_and_invalid_are_never_stale(self):
        """Neither a noncacheable answer nor untrusted input or a prohibited exit can authorize reuse."""
        self.ttl = 0
        self.assertIsNotNone(await self.cache.select(self.query))
        self.reply["fi"] = "servfail"
        self.assertIsNone(await self.cache.select(self.query))
        self.ttl = 2
        self.reply["fi"] = "203.0.113.11"
        await self.cache.select(self.query)
        self.now += 2
        self.reply["fi"] = "bad"
        self.assertIsNone(await self.cache.select(self.query))
        self.reply["fi"] = "timeout"
        before = len(self.calls)
        self.down.touch()
        self.assertIsNone(await self.cache.select(self.query))
        self.assertEqual(len(self.calls), before)

    async def test_mixed_contexts_veto_only_stale_and_explicit_negatives_remove_all_views(
        self,
    ):
        """A foreign negative vetoes stale only for this wave, and the origin's later negative clears every cached view."""
        q = dns.message.make_query("mixed.lab.test", "A")
        self.reply["fi"] = "203.0.113.11"
        self.reply["ru"] = "nxdomain"
        first = await self.cache.select(q)
        self.assertEqual(first.ip, "203.0.113.11")
        self.now += 2
        self.reply["fi"] = "servfail"
        self.assertIsNone(await self.cache.select(q))
        self.reply["ru"] = "timeout"
        self.assertEqual((await self.cache.select(q)).ip, first.ip)
        self.reply["fi"] = "ambiguous"
        self.assertIsNone(await self.cache.select(q))
        self.reply["fi"] = "timeout"
        self.assertEqual((await self.cache.select(q)).ip, first.ip)
        self.cache.winners["mixed.lab.test", ("fi",)] = rotation.Winner(
            "fi", first.ip, 9999
        )
        self.reply["fi"] = "nxdomain"
        self.reply["ru"] = "nxdomain"
        with self.assertRaises(rotation.NegativeAnswer):
            await self.cache.select(q)
        self.assertNotIn(("mixed.lab.test", ("fi",)), self.cache.winners)
        self.assertNotIn("mixed.lab.test", self.cache.retained)

    async def test_untrusted_servfail_and_negative_shapes(self):
        """Truncation, DNSSEC error details, refused and referral replies never permit stale or purge the prior entry."""
        initial = await self.cache.select(self.query)
        self.now += 2
        truncated = rotation.answer(self.query, code=2)
        truncated.flags |= dns.flags.TC
        ede = rotation.answer(self.query, code=2)
        ede.use_edns(options=[dns.edns.GenericOption(15, b"\x00\x06")])
        referral = rotation.answer(self.query)
        referral.authority.append(
            dns.rrset.from_text("only-fi.lab.test.", 30, "IN", "NS", "ns.lab.test.")
        )
        wrong_class = rotation.answer(self.query)
        wrong_class.authority.append(
            dns.rrset.from_text(
                "lab.test.", 30, "CH", "SOA", "ns.lab.test. admin.lab.test. 1 2 3 4 5"
            )
        )
        for reply in (
            truncated,
            ede,
            rotation.answer(self.query, code=5),
            referral,
            wrong_class,
        ):
            with mock.patch("cache.ask", return_value=reply):
                self.assertIsNone(await self.cache.select(self.query))
                self.assertEqual(self.cache.retained["only-fi.lab.test"], initial)
        self.reply["fi"] = "timeout"
        old = await self.cache.select(self.query)
        self.assertTrue(self.cache.permits_answer(self.query, old))
        self.down.touch()
        self.assertFalse(self.cache.permits_answer(self.query, old))

    async def test_fresh_soa_and_stale_supersession_at_delivery(self):
        """Forward a matching IN SOA for NODATA, and reject an already selected old answer after newer resolution."""
        await self.cache.select(self.query)
        self.now += 2
        self.reply["fi"] = "timeout"
        old = await self.cache.select(self.query)
        fresh = rotation.answer(self.query)
        soa = dns.rrset.from_text(
            "lab.test.", 30, "IN", "SOA", "ns.lab.test. admin.lab.test. 1 2 3 4 5"
        )
        fresh.authority.append(soa)
        with (
            mock.patch("cache.ask", return_value=fresh),
            self.assertRaises(rotation.NegativeAnswer) as neg,
        ):
            await self.cache.select(self.query)
        response = dns.message.from_wire(neg.exception.wire(self.query))
        self.assertEqual(response.rcode(), 0)
        self.assertEqual(response.authority, [soa])
        self.assertFalse(self.cache.permits_answer(self.query, old))

    async def test_dnssec_waiter_cannot_receive_unsigned_stale(self):
        """Coalescing a strict DNSSEC caller onto an ordinary pending timeout must not grant it stale eligibility."""
        await self.cache.select(self.query)
        self.now += 2
        start, release = asyncio.Event(), asyncio.Event()

        async def timeout(*args, **kw):
            """Hold the unsigned refresh while DO and CD callers join."""
            start.set()
            await release.wait()
            raise TimeoutError()

        do = dns.message.make_query("only-fi.lab.test.", "A", want_dnssec=True)
        cd = dns.message.make_query("only-fi.lab.test.", "A")
        cd.flags |= dns.flags.CD
        with mock.patch("cache.ask", side_effect=timeout):
            ordinary = asyncio.create_task(self.cache.select(self.query))
            await asyncio.wait_for(start.wait(), 1)
            waiters = [asyncio.create_task(self.cache.select(q)) for q in (do, cd)]
            await asyncio.sleep(0)
            release.set()
            value = await ordinary
            for q, waiter in zip((do, cd), waiters):
                self.assertIsNone(await waiter)
                self.assertFalse(self.cache.permits_answer(q, value))
