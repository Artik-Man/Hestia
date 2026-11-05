"""Exercise the Linux panel and sing-box journal on loopback in an isolated network namespace."""

import argparse
import json
import socket
import struct
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

API = "http://127.0.0.1:18081/api/traffic"


def request(path="", settings=None):
    """Read the local test API or PUT the supplied settings and return its decoded JSON."""
    data = None if settings is None else json.dumps(settings).encode()
    req = Request(API + path, data=data, method="GET" if data is None else "PUT")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=3) as response:
        return json.load(response)


def await_page(predicate):
    """Wait up to 15 seconds for the journal to satisfy a condition; report its last response on failure."""
    deadline = time.monotonic() + 15
    last = None
    while time.monotonic() < deadline:
        try:
            last = request()
            if predicate(last):
                return last
        except URLError as error:
            last = str(error)
        time.sleep(0.1)
    raise RuntimeError(f"Journal condition timed out: {last}")


def stop(process):
    """Terminate and reap exactly one process started by this test."""
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def udp_flow():
    """Send a SOCKS5 UDP datagram and verify delivery to the isolated loopback receiver."""
    with (
        socket.create_connection(("127.0.0.1", 18082), timeout=3) as control,
        control.makefile("rb") as reply,
        socket.socket(type=socket.SOCK_DGRAM) as receiver,
        socket.socket(type=socket.SOCK_DGRAM) as client,
    ):
        receiver.settimeout(3)
        receiver.bind(("127.0.0.1", 18083))
        control.sendall(bytes.fromhex("050100"))
        assert reply.read(2) == bytes.fromhex("0500")
        control.sendall(bytes.fromhex("05030001000000000000"))
        assert reply.read(4) == bytes.fromhex("05000001")
        relay_ip = socket.inet_ntoa(reply.read(4))
        (relay_port,) = struct.unpack("!H", reply.read(2))
        header = (
            bytes.fromhex("00000001")
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", 18083)
        )
        client.sendto(header + b"journal-udp", (relay_ip, relay_port))
        assert receiver.recv(128) == b"journal-udp"


def run(panel, engine, assets, snapshot):
    """Confirm a client request, durable settings, snapshot paging and recovery after panel restart."""
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
        work = Path(tmp)
        config = {
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
            "inbounds": [
                {"type": "socks", "listen": "127.0.0.1", "listen_port": 18082}
            ],
            "outbounds": [{"type": "direct", "tag": "lab-exit"}],
            "route": {"final": "lab-exit"},
        }
        config_path = work / "sing-box.json"
        config_path.write_text(json.dumps(config))
        cleanup.callback(stop, subprocess.Popen([engine, "run", "-c", config_path]))
        cmd = [
            panel,
            "-listen",
            "127.0.0.1:18081",
            "-assets",
            assets,
            "-snapshot",
            snapshot,
            "-traffic-capture",
            "-traffic-dir",
            work / "journal",
        ]
        with ExitStack() as first:
            first.callback(stop, subprocess.Popen(cmd))
            await_page(lambda page: page["sourceAvailable"])
            for _ in range(2):
                subprocess.run(
                    [
                        "curl",
                        "-fsS",
                        "--max-time",
                        "5",
                        "--noproxy",
                        "",
                        "--socks5",
                        "127.0.0.1:18082",
                        "-o",
                        "/dev/null",
                        "http://127.0.0.1:18081/",
                    ],
                    check=True,
                )
            udp_flow()
            page = await_page(lambda page: page["total"] >= 3)
            assert page["total"] == 3 and page["lost"] == 0, page
            assert all(
                event["address"] == "127.0.0.1"
                and (event["protocol"], event["port"])
                in {("TCP", 18081), ("UDP", 18083)}
                and event["connection"] == "lab-exit"
                and event["kind"] == "unconfirmed"
                for event in page["events"]
            ), page
            query = "?query=127.0.0&protocol=TCP&output=connection%3Alab-exit&limit=1"
            newest = request(query)
            older = request(query + "&offset=1&snapshot=" + newest["snapshot"])
            assert (
                newest["total"] == 2
                and older["events"][0]["id"] != newest["events"][0]["id"]
            )
            assert request("?protocol=UDP")["total"] == 1
            settings = {"maxMB": 16, "retentionHours": 72}
            change = {"expected": request("/settings"), "proposed": settings}
            assert request("/settings", change) == settings
        cleanup.callback(stop, subprocess.Popen(cmd))
        recovered = await_page(
            lambda page: page["sourceAvailable"] and page["total"] == 3
        )
        assert request("/settings") == settings
        assert recovered["lastInterruption"]
        print(
            json.dumps(
                {
                    "observations": recovered["events"],
                    "lost": recovered["lost"],
                    "settingsAfterRestart": settings,
                    "paging": "passed",
                    "lastInterruption": recovered["lastInterruption"],
                }
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("panel", "engine", "assets", "snapshot"):
        parser.add_argument(argument, type=Path)
    args = parser.parse_args()
    run(*(path.resolve() for path in vars(args).values()))
