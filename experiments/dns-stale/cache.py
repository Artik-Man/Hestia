#!/usr/bin/python3
"""Experimental stale-if-error policy restricted to controlled unsigned single-A replies."""

import argparse
import asyncio
import importlib
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

import dns.exception
import dns.flags
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
rotation = importlib.import_module("dns-rotation.cache")
ask = rotation.ask
LAB_ZONE = dns.name.from_text("lab.test.")
MAX_NAMES = 128
MAX_PENDING = 64


@dataclass(frozen=True)
class Fresh(rotation.Winner):
    """Distinguish a positive zero TTL, usable only for the obtaining transaction."""

    ttl: int


@dataclass(frozen=True)
class Previous(rotation.Winner):
    """Mark an expired positive as a per-request fallback; its original expiry is immutable."""

    groups: tuple[str, ...]
    generations: tuple[int, ...]


@dataclass(frozen=True)
class Observation:
    """Represent a bounded resolver attempt and distinguish true negatives from transient failures."""

    group: str
    kind: str
    value: rotation.Winner | None = None
    ttl: int = 0
    code: int | None = None
    soa: tuple = ()
    generation: int = 0


def supported(query):
    """Admit only unsigned lab.test A callers, including when multiple requests would share an upstream wave."""
    return bool(
        query.question[0].name.is_subdomain(LAB_ZONE)
        and not (
            query.ednsflags & dns.flags.DO
            or query.flags & (dns.flags.CD | dns.flags.AD)
        )
    )


class StaleCache(rotation.WinnerCache):
    """Remember selected positive records and authorize stale responses only after a complete failed refresh."""

    def __init__(self, down, window=0, clock=monotonic):
        """Configure zero for strict mode, or a bounded lab-only stale interval following original expiry."""
        super().__init__(down)
        if (
            type(window) not in (int, float)
            or not math.isfinite(window)
            or not 0 <= window <= 86400
        ):
            raise ValueError(
                "stale interval must be finite and within 0..86400 seconds"
            )
        self.window = window
        self.clock = clock
        self.retained = {}
        self.sequence = 0
        self.latest = {}

    async def select(self, query):
        """Coalesce eligible waves and limit retained names, active waves and live winner views."""
        if not supported(query):
            rotation.log(
                "stale-denied", domain=rotation.name(query), reason="unsigned_lab_only"
            )
            return None
        now = self.clock()
        for key, value in list(self.winners.items()):
            if value.expires <= now:
                self.winners.pop(key, None)
        domain = rotation.name(query)
        groups = self.allowed(query)
        if not groups:
            rotation.log("stale-denied", domain=domain, reason="ineligible")
            return None
        if (
            len(self.inflight) >= MAX_PENDING
            and (domain, groups) not in self.inflight
            and (domain, groups) not in self.winners
        ):
            rotation.log("stale-denied", domain=domain, reason="capacity")
            return None
        try:
            return await super().select(query)
        finally:
            while len(self.winners) > MAX_NAMES * 4:
                self.winners.pop(next(iter(self.winners)))

    def retain(self, domain, selected, ttl):
        """Replace the last committed winner; a TTL of zero clears any earlier emergency option."""
        self.retained.pop(domain, None)
        if self.window and ttl > 0:
            self.retained[domain] = selected
            while len(self.retained) > MAX_NAMES:
                self.retained.pop(next(iter(self.retained)))

    def permits_answer(self, query, selected):
        """Recheck the retained identity, eligible contexts and stale deadline immediately before wire delivery."""
        if not supported(query):
            return False
        if not isinstance(selected, Previous):
            key = rotation.name(query), self.allowed(query)
            return (
                super().permits_answer(query, selected)
                and self.winners.get(key) is selected
                and (
                    isinstance(selected, Fresh)
                    and selected.ttl == 0
                    or selected.expires > self.clock()
                )
            )
        domain = rotation.name(query)
        old = self.retained.get(domain)
        age = self.clock() - selected.expires
        if (
            old is None
            or (old.group, old.ip, old.expires)
            != (selected.group, selected.ip, selected.expires)
            or self.allowed(query) != selected.groups
            or tuple(self.latest.get((domain, g)) for g in selected.groups)
            != selected.generations
            or not 0 <= age < self.window
        ):
            rotation.log(
                "stale-denied",
                domain=domain,
                group=selected.group,
                reason="recheck_failed",
            )
            return False
        rotation.log(
            "stale-served",
            domain=domain,
            group=selected.group,
            ip=selected.ip,
            age=age,
            original_expiry_ns=int(selected.expires * 1e9),
            stale_seconds=self.window,
            ttl=0,
            reason="all_temporary",
        )
        return True

    async def probe(self, query, group, prior):
        """Classify an exact reply; malformed, truncated and extended failures never authorize stale reuse."""
        domain = rotation.name(query)
        if group not in self.allowed(query):
            return Observation(group, "ineligible")
        source = domain, group
        self.sequence += 1
        generation = self.sequence
        self.latest.pop(source, None)
        self.latest[source] = generation
        while len(self.latest) > MAX_NAMES * 4:
            self.latest.pop(next(iter(self.latest)))
        rotation.log("start", domain=domain, group=group)
        try:
            reply = await ask(query, rotation.RESOLVER[group], group=group)
        except TimeoutError:
            return Observation(group, "timeout", generation=generation)
        except (OSError, dns.exception.DNSException):
            return Observation(group, "invalid")
        if self.latest.get(source) != generation or group not in self.allowed(query):
            return Observation(group, "superseded")
        code = reply.rcode()
        if (
            reply.flags & dns.flags.TC
            or reply.question != query.question
            or any(int(option.otype) == 15 for option in reply.options)
        ):
            return Observation(group, "invalid")
        if code == dns.rcode.SERVFAIL:
            return Observation(group, "servfail", generation=generation)
        rr = rotation.direct_a(query, reply)
        if code == dns.rcode.NOERROR and rr is not None and len(reply.answer) == 1:
            value = Fresh(group, rr[0].address, self.clock() + rr.ttl, rr.ttl)
            return Observation(
                group, "positive", value, rr.ttl, code, generation=generation
            )
        # Referrals and unsupported answer shapes cannot prove the name/type absent.
        soa = tuple(
            r
            for r in reply.authority
            if r.rdtype == dns.rdatatype.SOA
            and r.rdclass == dns.rdataclass.IN
            and query.question[0].name.is_subdomain(r.name)
        )
        referral = bool(reply.authority) and not soa
        if (
            code not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
            or reply.answer
            or referral
            or not (soa or reply.flags & dns.flags.AA)
        ):
            return Observation(group, "invalid")
        self.invalidate_views(domain, group)
        if prior and prior.group == group and self.retained.get(domain) is prior:
            self.retained.pop(domain)
        return Observation(group, "negative", code=code, soa=soa, generation=generation)

    def invalidate_views(self, domain, group):
        """Remove obsolete winners from this source even under other eligible-set cache keys."""
        for key, record in list(self.winners.items()):
            if key[0] == domain and record.group == group:
                del self.winners[key]

    async def refresh(self, query, groups):
        """Prefer any fresh positive, return agreed negatives, and consider stale only on all-temporary outcomes."""
        domain = rotation.name(query)
        if len(self.pending) + len(groups) > MAX_PENDING:
            rotation.log("stale-denied", domain=domain, reason="capacity")
            return None
        prior = self.retained.get(domain)
        tasks = [asyncio.create_task(self.probe(query, g, prior)) for g in groups]
        self.pending.update(tasks)
        for task in tasks:
            task.add_done_callback(self.pending.discard)
        outcomes = []
        for future in asyncio.as_completed(tasks):
            obs = await future
            outcomes.append(obs)
            rotation.log(
                "finish",
                domain=domain,
                group=obs.group,
                kind=obs.kind,
                code=obs.code,
                ip=obs.value.ip if obs.value else None,
                ttl=obs.ttl,
            )
            if (
                obs.value
                and self.allowed(query) == groups
                and self.latest.get((domain, obs.group)) == obs.generation
            ):
                self.invalidate_views(domain, obs.group)
                self.winners[domain, groups] = obs.value
                self.retain(domain, obs.value, obs.ttl)
                rotation.log(
                    "selected", domain=domain, group=obs.group, ip=obs.value.ip
                )
                return obs.value
        if groups != self.allowed(query):
            rotation.log("stale-denied", domain=domain, reason="ineligible")
            return None
        negatives = [o for o in outcomes if o.kind == "negative"]
        if negatives:
            rotation.log("stale-denied", domain=domain, reason="negative_answer")
            if (
                len(negatives) == len(groups)
                and len({o.code for o in negatives}) == 1
                and all(
                    self.latest.get((domain, o.group)) == o.generation
                    for o in negatives
                )
            ):
                best = next(o for o in negatives if o.group == groups[0])
                raise rotation.NegativeAnswer(groups, best.code, best.soa)
            return None
        reason = None
        if not self.window:
            reason = "disabled"
        elif any(
            o.kind not in ("timeout", "servfail")
            or self.latest.get((domain, o.group)) != o.generation
            for o in outcomes
        ):
            reason = "not_temporary"
        elif prior is None or self.retained.get(domain) is not prior:
            reason = "no_candidate"
        elif prior.group not in groups:
            reason = "ineligible"
        elif not 0 <= self.clock() - prior.expires < self.window:
            reason = "outside_window"
        if reason:
            rotation.log("stale-denied", domain=domain, reason=reason)
            return None
        return Previous(
            prior.group,
            prior.ip,
            prior.expires,
            groups,
            tuple(self.latest[domain, g] for g in groups),
        )


async def main():
    """Run a strict gateway by default, or test the explicitly requested stale interval."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gateway"])
    parser.add_argument("--down", type=Path, default=Path("fi-down"))
    parser.add_argument("--stale-seconds", type=float, default=0)
    args = parser.parse_args()
    await rotation.gateway(args.down, StaleCache(args.down, args.stale_seconds))


if __name__ == "__main__":
    asyncio.run(main())
