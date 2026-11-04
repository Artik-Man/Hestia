#!/usr/bin/python3
"""Experimental single-A DNS arbitration for both client DNS and new FakeIP data flows."""

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dns-geo"))
from fixture import GROUPS, RESOLVER, answer, ask, bind, log, name, unpack


@dataclass(frozen=True)
class Winner:
    """Keep the resolver identity and real address with the monotonic expiry of that response."""

    group: str
    ip: str
    expires: float

    def remaining(self) -> int:
        """Return whole seconds remaining without extending the upstream TTL."""
        return max(0, int(self.expires - monotonic()))


class WinnerCache:
    """Own separate upstream observations and a single selected response per eligible resolver set."""

    def __init__(self, down: Path):
        """Start the disposable lab cache and track pending lookup waves and late candidates."""
        self.down = down
        self.winners = {}
        self.inflight = {}
        self.pending = set()

    def allowed(self, query: dns.message.Message) -> tuple[str, ...]:
        """Derive eligible resolvers from the case-insensitive suffix rule and current FI marker."""
        explicit = query.question[0].name.is_subdomain(
            dns.name.from_text("only-fi.lab.test.")
        )
        groups = ("fi",) if explicit else GROUPS
        return tuple(g for g in groups if g != "fi" or not self.down.exists())

    async def lookup(self, query: dns.message.Message, group: str) -> Winner | None:
        """Query one allowed resolver and log its candidate and TTL without changing the winner."""
        domain = name(query)
        if group not in self.allowed(query):
            log("blocked-before-send", domain=domain, group=group)
            return None
        log("start", domain=domain, group=group)
        try:
            reply = await ask(query, RESOLVER[group], group=group)
        except (OSError, TimeoutError, dns.exception.DNSException):
            log("upstream-error", domain=domain, group=group)
            return None
        matches = [
            rr
            for rr in reply.answer
            if rr.name == query.question[0].name
            and rr.rdclass == dns.rdataclass.IN
            and rr.rdtype == dns.rdatatype.A
            and len(rr) == 1
        ]
        if reply.rcode() != dns.rcode.NOERROR or len(matches) != 1:
            log("finish", domain=domain, group=group, code=reply.rcode(), ip=None)
            return None
        rr = matches[0]
        value = Winner(group, rr[0].address, monotonic() + rr.ttl)
        log(
            "finish",
            domain=domain,
            group=group,
            code=reply.rcode(),
            ip=value.ip,
            ttl=rr.ttl,
        )
        return value

    async def refresh(
        self, query: dns.message.Message, groups: tuple[str, ...]
    ) -> Winner | None:
        """Commit the first usable result while the other resolver attempts finish independently."""
        domain = name(query)
        tasks = [asyncio.create_task(self.lookup(query, g)) for g in groups]
        self.pending.update(tasks)
        for task in tasks:
            task.add_done_callback(self.pending.discard)
        for result in asyncio.as_completed(tasks):
            candidate = await result
            if candidate and candidate.group in self.allowed(query):
                self.winners[domain, groups] = candidate
                log("selected", domain=domain, group=candidate.group, ip=candidate.ip)
                return candidate
        return None

    async def select(self, query: dns.message.Message) -> Winner | None:
        """Reuse a fresh eligible winner or coalesce concurrent flows into one upstream wave."""
        groups = self.allowed(query)
        domain = name(query)
        if not groups:
            log("blocked", domain=domain)
            return None
        key = domain, groups
        known = self.winners.get(key)
        if known and known.expires > monotonic():
            log("hit", domain=domain, group=known.group, ip=known.ip)
            return known
        task = self.inflight.get(key)
        if task is None or task.done():
            task = self.inflight[key] = asyncio.create_task(self.refresh(query, groups))
        try:
            selected = await asyncio.shield(task)
        finally:
            if task.done() and self.inflight.get(key) is task:
                del self.inflight[key]
        return selected if selected and selected.group in self.allowed(query) else None


async def gateway(down: Path, cache=None, client_select=None) -> None:
    """Serve FakeIP requests on LAN and resolve real addresses independently for new sing-box flows."""
    if cache is None:
        cache = WinnerCache(down)

    async def respond(data: bytes, client_dns: bool, peer) -> bytes | None:
        """Use the same arbitration for both listeners; only the client listener asks the FakeIP issuer."""
        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException:
            return None
        if query.flags & dns.flags.QR:
            return None
        if query.opcode() != dns.opcode.QUERY:
            return answer(query, code=dns.rcode.NOTIMP).to_wire()
        if (
            len(query.question) != 1
            or query.question[0].rdtype != dns.rdatatype.A
            or query.question[0].rdclass != dns.rdataclass.IN
        ):
            return answer(query, code=dns.rcode.REFUSED).to_wire()
        if client_dns and client_select is not None:
            selected = await client_select(query, peer)
        else:
            selected = await cache.select(query)
        if selected is None:
            return answer(query, code=dns.rcode.SERVFAIL).to_wire()
        addr = selected.ip
        if client_dns:
            addr = unpack(await ask(query, "127.0.0.1", 1054))
            if not addr or selected.group not in cache.allowed(query):
                return answer(query, code=dns.rcode.SERVFAIL).to_wire()
            log(
                "serve",
                domain=name(query),
                group=selected.group,
                ip=selected.ip,
                fake=addr,
            )
        else:
            log("real", domain=name(query), group=selected.group, ip=selected.ip)
        return answer(query, addr, ttl=selected.remaining()).to_wire()

    services = [
        await bind("10.85.0.1", 53, lambda data, peer: respond(data, True, peer)),
        await bind("127.0.0.1", 1055, lambda data, peer: respond(data, False, peer)),
    ]
    log("ready")
    try:
        await asyncio.Future()
    finally:
        for transport, _ in services:
            transport.close()


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or sys.argv[1] != "gateway":
        sys.exit("Usage: cache.py gateway [FI_DOWN_MARKER]")
    asyncio.run(gateway(Path(sys.argv[2]) if len(sys.argv) == 3 else Path("fi-down")))
