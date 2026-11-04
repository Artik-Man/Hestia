"""Return deterministic A, NXDOMAIN or SERVFAIL responses, or deliberately drop the DNS reply."""

import asyncio
import json
import sys
from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dns-rotation"))
import peer

TTL = 2


async def main(group: str, state: Path) -> None:
    """Start the controlled resolver and address-labelled TCP/UDP echo endpoints inside one peer namespace."""

    async def resolve(data: bytes, source: tuple) -> bytes | None:
        """Log the actual inbound request and apply the named failure mode at the authoritative peer."""
        query = dns.message.from_wire(data)
        domain = peer.fixture.name(query)
        generation = json.loads(state.read_text()).get(domain, "old")
        address = {"old": peer.OLD, "new": peer.NEW}.get(generation)
        peer.fixture.log(
            "authority",
            group=group,
            domain=domain,
            mode=generation,
            source=source[0],
            ip=address,
        )
        if generation == "drop":
            return None
        if generation not in ("old", "new", "nx", "empty", "servfail"):
            raise ValueError("unknown DNS mode")
        rcode = {"nx": dns.rcode.NXDOMAIN, "servfail": dns.rcode.SERVFAIL}.get(
            generation, dns.rcode.NOERROR
        )
        msg = peer.fixture.answer(query, address, rcode, ttl=TTL)
        if generation in ("nx", "empty"):
            msg.authority.append(
                dns.rrset.from_text(
                    "lab.test.",
                    TTL,
                    "IN",
                    "SOA",
                    "ns.lab.test. admin.lab.test. 1 60 60 60 2",
                )
            )
        msg.flags |= dns.flags.AA
        return msg.to_wire()

    await peer.serve(group, state, resolve)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], Path(sys.argv[2])))
