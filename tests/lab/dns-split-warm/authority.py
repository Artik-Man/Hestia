"""Serve different eligible answers and TTLs per physical uplink for a shared DNS name."""

import asyncio
import importlib
import json
import sys
from pathlib import Path

import dns.flags
import dns.message

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
peer = importlib.import_module("dns-rotation.peer")

RU_A, FI_A, RU_B = peer.fixture.IPS
TTLS = {"ru": 4, "fi": 16}


async def serve(group: str, state: Path) -> None:
    """Bind a deterministic split-horizon authority and address-labelled TCP/UDP echo endpoints."""

    async def answer(data: bytes, source: tuple) -> bytes:
        """Return the source-specific A with its independent TTL, logging the actual request and generation."""
        q = dns.message.from_wire(data)
        await asyncio.sleep(0.012 if group == "fi" else 0.065)
        salt = state.read_text().strip()
        ip = (
            FI_A
            if group == "fi"
            else {"first": RU_B, "second": RU_A, "third": RU_B}[salt]
        )
        msg = peer.fixture.answer(q, ip, ttl=TTLS[group])
        msg.flags |= dns.flags.AA
        peer.fixture.log(
            "authority",
            source=source[0],
            group=group,
            domain=peer.fixture.name(q),
            ip=ip,
            ttl=TTLS[group],
            generation=salt,
        )
        return msg.to_wire()

    # Listen on a third real test IP as well as the two inherited peer addresses.
    async def udp(data: bytes, source: tuple) -> bytes:
        """Echo and log the third destination's UDP marker and actual source for independent path verification."""
        return response(data, source[0], "udp")

    def response(data: bytes, source: str, proto: str) -> bytes:
        """Encode a reply tied to the third address and this peer's actual physical interface."""
        result = {
            "ip": RU_B,
            "group": group,
            "proto": proto,
            "source": source,
            "token": data.decode().strip(),
        }
        peer.fixture.log("peer", **result)
        return (json.dumps(result) + "\n").encode()

    async def tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Echo an accepted TCP marker for the additional RU address and close the connection."""
        try:
            data = await reader.readline()
            if data:
                writer.write(
                    response(data, writer.get_extra_info("peername")[0], "tcp")
                )
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    endpoints = [
        await peer.fixture.bind(RU_B, peer.PORT, udp),
        await asyncio.start_server(tcp, RU_B, peer.PORT),
    ]
    try:
        await peer.serve(group, state, answer)
    finally:
        endpoints[0][0].close()
        endpoints[1].close()


if __name__ == "__main__":
    asyncio.run(serve(sys.argv[1], Path(sys.argv[2])))
