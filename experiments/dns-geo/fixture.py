#!/usr/bin/python3
"""Lab-only IPv4/A DNS arbitration and synthetic controlled services."""
import asyncio
import json
from pathlib import Path
import socket
import sys
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

GROUPS = ("ru", "fi")
IPS = ("203.0.113.11", "203.0.113.22", "203.0.113.33")
RESOLVER = {"ru": "10.85.1.2", "fi": "10.85.2.2"}
TTL = 45


def log(event, **data):
    """Write a structured lab event with a monotonic timestamp for ordering DNS and flow decisions."""
    print(json.dumps(dict(event=event, ns=time.monotonic_ns(), **data)), flush=True)


def name(query):
    """Return the question's canonical lower-case DNS name without the terminal root dot."""
    return query.question[0].name.canonicalize().to_text().rstrip(".")


def answer(query, ip=None, code=dns.rcode.NOERROR, ttl=TTL):
    """Build a response to the original question with the requested RCODE and optional IPv4 address and TTL."""
    response = dns.message.make_response(query)
    response.set_rcode(code)
    if ip:
        response.answer.append(dns.rrset.from_text(query.question[0].name, ttl, "IN", "A", ip))
    return response


def unpack(reply):
    """Return the first IPv4 address in the answer section, or None when there is no A record."""
    ips = [r.address for rr in reply.answer if rr.rdtype == 1 for r in rr]
    return ips[0] if ips else None


class Service(asyncio.DatagramProtocol):
    """Dispatch UDP fixture requests concurrently and retain pending tasks until their replies are sent."""
    def __init__(self, handle):
        """Store the async request handler and initialize the collection of outstanding replies."""
        self.handle = handle
        self.pending = set()

    def connection_made(self, transport):
        """Keep the bound transport for sending replies to their original callers."""
        self.transport = transport

    def datagram_received(self, data, peer):
        """Schedule a reply for this datagram and release the task reference when it finishes."""
        task = asyncio.create_task(self.reply(data, peer))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def reply(self, data, peer):
        """Run the fixture handler and return its encoded response to the requesting peer."""
        self.transport.sendto(await self.handle(data, peer), peer)


async def bind(addr, port, handle):
    """Create a UDP server bound to the supplied address and port using the given async handler."""
    return await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Service(handle), local_addr=(addr, port))


async def serve_peer(group):
    """Run the selected group's delayed DNS responder and address-labelled UDP echo endpoints."""
    async def resolve(data, peer):
        """Apply the scenario's delay and answer policy, then log the resolver and chosen IPv4 or NXDOMAIN."""
        query = dns.message.from_wire(data)
        domain = name(query)
        label = domain.split(".")[0]
        fast = "ru" if label in ("fast-ru", "negative") else "fi"
        await asyncio.sleep(0.03 if group == fast else (0.18 if label == "negative" else 0.75))
        ip = IPS[0] if group == "fi" else IPS[1]
        if label == "unknown":
            ip = IPS[2]
        if label == "ru-control":
            ip = IPS[0]
        nx = label == "negative" and group == "ru"
        log("resolver", domain=domain, group=group, ip=None if nx else ip, peer=peer[0])
        return answer(query, None if nx else ip, dns.rcode.NXDOMAIN if nx else 0).to_wire()

    async def echo(data, peer):
        """Return the observed source, group, destination and request token as a JSON datagram."""
        token, ip = data.decode().split("|")
        log("echo", group=group, peer=peer[0], ip=ip, token=token)
        return json.dumps(dict(group=group, ip=ip, token=token, source=peer[0])).encode()

    services = [await bind(RESOLVER[group], 53, resolve)]
    for address in IPS:
        # Verify the packet reached the specific destination address.
        async def at_address(data, peer, addr=address):
            """Pass the receiving socket's real destination address to the echo handler."""
            return await echo(data + b"|" + addr.encode(), peer)
        services.append(await bind(address, 19091, at_address))
    log("ready")
    await asyncio.Future()


async def ask(query, addr, port=53, group=None):
    """Send one bounded UDP DNS query, optionally bound to a group interface, and validate its reply."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if group:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (group + "0").encode())
        s.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(s, query.to_wire(), (addr, port))
        wire, origin = await asyncio.wait_for(loop.sock_recvfrom(s, 4096), 2)
        if origin != (addr, port):
            raise OSError("DNS reply arrived from an unexpected endpoint")
        reply = dns.message.from_wire(wire)
        if not query.is_response(reply):
            raise OSError("DNS reply does not match the request")
        return reply


async def gateway(down):
    # Winner and other completed candidates retain their per-uplink provenance.
    """Serve client DNS and committed real-IP lookups using group-scoped candidates and TTLs."""
    candidates, winners, pending = {}, {}, set()

    async def lookup(query, group):
        """Query one group's resolver and retain a successful result with its provenance and expiry."""
        domain = name(query)
        log("start", domain=domain, group=group)
        reply = await ask(query, RESOLVER[group], group=group)
        ip = unpack(reply)
        if ip:
            ttl = reply.answer[0].ttl
            candidates[domain, group] = (ip, time.monotonic() + ttl)
        log("finish", domain=domain, group=group, ip=ip, code=reply.rcode(),
            ttl=reply.answer[0].ttl if ip else None)
        return group, ip

    async def frontend(data, peer):
        """Enforce group eligibility, select or reuse a live A candidate, and return the associated FakeIP."""
        query = dns.message.from_wire(data)
        domain = name(query)
        explicit = query.question[0].name.is_subdomain(dns.name.from_text("only-fi.lab.test."))
        allowed = ["fi"] if explicit else list(GROUPS)
        if down.exists():
            allowed = [g for g in allowed if g != "fi"]
        if not allowed:
            log("blocked", domain=domain)
            return answer(query, code=dns.rcode.SERVFAIL).to_wire()
        cached = winners.get(domain)
        if cached and cached[0] in allowed and cached[2] > time.monotonic():
            group, ip, _ = cached
            log("hit", domain=domain, group=group, ip=ip)
        elif (available := [(g, candidates[domain, g]) for g in allowed
                            if (domain, g) in candidates and candidates[domain, g][1] > time.monotonic()]):
            group, (ip, expiry) = available[0]
            winners[domain] = (group, ip, expiry)
            log("reuse-candidate", domain=domain, group=group, ip=ip)
        else:
            tasks = [asyncio.create_task(lookup(query, g)) for g in allowed]
            pending.update(tasks)
            for task in tasks:
                task.add_done_callback(pending.discard)
            for future in asyncio.as_completed(tasks):
                try:
                    group, ip = await future
                except (OSError, TimeoutError):
                    continue
                if ip:
                    expiry = candidates[domain, group][1]
                    winners[domain] = (group, ip, expiry)
                    log("selected", domain=domain, group=group, ip=ip)
                    break
            else:
                return answer(query, code=dns.rcode.SERVFAIL).to_wire()
        reply = await ask(query, "127.0.0.1", 1054)
        fake = unpack(reply)
        log("serve", domain=domain, ip=ip, fake=fake)
        remaining = max(0, int(winners[domain][2] - time.monotonic()))
        return answer(query, fake, ttl=remaining).to_wire()

    async def committed(data, peer):
        """Return the chosen real IPv4 address to sing-box while its cached answer is still valid."""
        query = dns.message.from_wire(data)
        domain = name(query)
        cached = winners.get(domain)
        ip = cached[1] if cached and cached[2] > time.monotonic() else None
        log("real", domain=domain, ip=ip)
        return answer(query, ip, 0 if ip else dns.rcode.SERVFAIL,
                      ttl=max(0, int(cached[2] - time.monotonic())) if ip else 0).to_wire()

    services = [await bind("10.85.0.1", 53, frontend), await bind("127.0.0.1", 1055, committed)]
    log("ready")
    await asyncio.Future()


async def client(case, state):
    """Exercise one case, recording DNS latency, FakeIP reuse and the UDP service's observed egress."""
    domain = {"explicit": "fixed.only-fi.lab.test", "blocked": "cold.only-fi.lab.test",
              "warm": "fast-fi.lab.test", "cached-down": "fixed.only-fi.lab.test",
              "apex": "only-fi.lab.test", "apex-down": "only-fi.lab.test",
              "ru-control": "ru-control.lab.test"}.get(case, case + ".lab.test")
    saved = json.loads(state.read_text()) if state.exists() else {}
    t0 = time.monotonic_ns()
    if case == "cached-down":
        fake = saved[domain]
        code = None
    else:
        query = dns.message.make_query(domain.upper() if case in ("apex", "apex-down") else domain, "A")
        reply = await ask(query, "10.85.0.1")
        code, fake = reply.rcode(), unpack(reply)
    dns_ns = time.monotonic_ns()
    if fake:
        saved[domain] = fake
        state.write_text(json.dumps(saved))
    token = "probe-" + case
    response = None
    if fake:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(s, token.encode(), (fake, 19091))
            try:
                wire, _ = await asyncio.wait_for(loop.sock_recvfrom(s, 4096), 0.7)
                response = json.loads(wire)
            except asyncio.TimeoutError:
                pass
    log("client", case=case, domain=domain, token=token, fake=fake, code=code, response=response,
        dns_ms=(dns_ns-t0)/1e6, dns_done_ns=dns_ns)


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "peer":
        asyncio.run(serve_peer(*args))
    elif action == "gateway":
        asyncio.run(gateway(Path(args[0])))
    elif action == "client":
        asyncio.run(client(args[0], Path(args[1])))
