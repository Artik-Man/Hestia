"""Private authoritative DNS and TCP/UDP service peers for the controlled A-record rotation."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dns-geo"))
import dns.flags
import dns.message
import fixture

TTL = 4
OLD, NEW = fixture.IPS[:2]
PORT = 19091


async def serve(group: str, state: Path, dns_handler=None) -> None:
    """Serve the supplied DNS behavior or the rotation authority, together with the shared TCP/UDP peers."""

    async def resolve(data: bytes, peer: tuple) -> bytes:
        """Return the selected generation at response time, with predictable resolver completion order."""
        query = dns.message.from_wire(data)
        await asyncio.sleep(0.015 if group == "fi" else 0.06)
        current = state.read_text().strip()
        if current not in ("old", "new"):
            raise ValueError("invalid authoritative record state")
        ip = OLD if current == "old" else NEW
        reply = fixture.answer(query, ip, ttl=TTL)
        reply.flags |= dns.flags.AA
        fixture.log(
            "authority",
            group=group,
            domain=fixture.name(query),
            ip=ip,
            ttl=TTL,
            source=peer[0],
        )
        return reply.to_wire()

    def reply(data: bytes, source: str, addr: str, proto: str) -> bytes:
        """Tag actual receiving interface, address, transport and source in the reply and peer log."""
        record = {
            "token": data.decode().strip(),
            "group": group,
            "ip": addr,
            "source": source,
            "proto": proto,
        }
        fixture.log("peer", **record)
        return (json.dumps(record) + "\n").encode()

    async def tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Return the actual peer observation from the accepted TCP connection."""
        try:
            data = await asyncio.wait_for(reader.readline(), 1)
            if data:
                writer.write(
                    reply(
                        data,
                        writer.get_extra_info("peername")[0],
                        writer.get_extra_info("sockname")[0],
                        "tcp",
                    )
                )
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    listeners = [
        await fixture.bind(fixture.RESOLVER[group], 53, dns_handler or resolve)
    ]
    for address in (OLD, NEW):

        async def udp(data: bytes, peer: tuple, addr=address) -> bytes:
            """Echo a tagged UDP request with the receiving socket's bound address."""
            return reply(data, peer[0], addr, "udp")

        listeners.append(await fixture.bind(address, PORT, udp))
        listeners.append(await asyncio.start_server(tcp, address, PORT))
    fixture.log("ready")
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(serve(sys.argv[1], Path(sys.argv[2])))
