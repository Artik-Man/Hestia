"""Check country routing, live exact-IP overrides and domain precedence on isolated loopback."""

import argparse
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "deploy"))
import profile as compiler


class Target(http.server.BaseHTTPRequestHandler):
    """Return a unique local success marker for each completed HTTP probe."""

    def do_GET(self):
        """Acknowledge the probe without contacting external services."""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hestia-country-ok")

    def log_message(self, fmt, *args):
        """Keep the report limited to the outcome of each controlled probe."""


def free_port():
    """Reserve and release a temporary loopback TCP port for the private sing-box listener."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def probe(proxy, target, host):
    """Send one IPv4 SOCKS5 request and prove that the HTTP target received it."""
    try:
        with socket.create_connection(("127.0.0.1", proxy), timeout=1) as conn:
            conn.settimeout(1)
            stream = conn.makefile("rb")
            conn.sendall(b"\x05\x01\x00")
            if stream.read(2) != b"\x05\x00":
                return False
            conn.sendall(
                b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big")
            )
            # sing-box may wait for payload before returning SOCKS success during protocol sniffing.
            conn.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            return b"hestia-country-ok" in stream.read()
    except OSError:
        return False


def check_changes(binary, directory):
    """Run an unprivileged sing-box instance and exercise route selection without restarting it."""
    codes = (
        (Path(__file__).resolve().parents[3] / "backend/internal/geoip/countries.txt")
        .read_text()
        .split()
    )
    compiler.GEOIP_DIRECTORY = directory / "base"
    compiler.GEOIP_OVERRIDES = directory / "overrides"
    compiler.GEOIP_DIRECTORY.mkdir()
    compiler.GEOIP_OVERRIDES.mkdir()
    empty = json.dumps({"version": 3, "rules": []})
    matched = json.dumps({"version": 3, "rules": [{"ip_cidr": ["127.0.0.1/32"]}]})
    for code in codes:
        (compiler.GEOIP_OVERRIDES / (code + ".json")).write_text(empty)
    (compiler.GEOIP_DIRECTORY / "manifest.json").write_text(
        json.dumps({"countries": ["RU"]})
    )
    (compiler.GEOIP_DIRECTORY / "RU.json").write_text(matched)
    policy = {
        "version": "test",
        "enabled": True,
        "assignments": dict.fromkeys(codes, "fallback"),
    }
    policy["assignments"]["RU"] = "pass"
    profile = {
        "groups": [{"id": "fallback"}, {"id": "pass"}],
        "inbounds": [{"type": "tun", "tag": "client"}],
        "countryMap": policy,
    }
    route = compiler.client_route(
        profile,
        "fallback",
        [{"domain_suffix": "mask.test", "action": "route", "outbound": "pass"}],
        [],
    )
    proxy_port = free_port()
    with (
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target) as server,
        socket.socket() as refused,
    ):
        refused.bind(("127.0.0.1", 0))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cfg = {
            "log": {"level": "debug"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "client",
                    "listen": "127.0.0.1",
                    "listen_port": proxy_port,
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "pass"},
                {
                    "type": "socks",
                    "tag": "fallback",
                    "server": "127.0.0.1",
                    "server_port": refused.getsockname()[1],
                },
            ],
            "route": route,
        }
        path = directory / "config.json"
        path.write_text(json.dumps(cfg))
        subprocess.run([binary, "check", "-c", path], check=True)
        with (
            (directory / "logs").open("w") as logs,
            subprocess.Popen(
                [binary, "run", "-c", path], stdout=logs, stderr=logs
            ) as proc,
        ):
            try:
                for _ in range(80):
                    if probe(proxy_port, server.server_port, "plain.test"):
                        break
                    if proc.poll() is not None:
                        raise RuntimeError((directory / "logs").read_text()[-4500:])
                    time.sleep(0.05)
                else:
                    raise RuntimeError(
                        "DB-IP country failed: "
                        + (directory / "logs").read_text()[-4500:]
                    )
                print("DB-IP RU delivered HTTP over the assigned pass group")
                temp = compiler.GEOIP_OVERRIDES / "next"
                temp.write_text(matched)
                os.replace(temp, compiler.GEOIP_OVERRIDES / "FI.json")
                for _ in range(80):
                    if not probe(proxy_port, server.server_port, "plain.test"):
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError(
                        "updated exact-IP country failed to override DB-IP"
                    )
                if proc.poll() is not None or not probe(
                    proxy_port, server.server_port, "a.mask.test"
                ):
                    raise RuntimeError("sniffed domain did not override exact country")
                print(
                    "Atomic FI override switched subsequent flows to refusing fallback without a restart"
                )
                print(
                    "HTTP host matched explicit domain rule and reached target despite FI override"
                )
            finally:
                proc.terminate()
                server.shutdown()
        if "watch rule-set file" in (directory / "logs").read_text():
            raise RuntimeError("at least one rule-set failed to subscribe to updates")


def main():
    """Run all probes against a caller-selected sing-box binary without touching a gateway."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    subprocess.run([args.binary, "version"], check=True)
    with tempfile.TemporaryDirectory() as temp:
        check_changes(args.binary, Path(temp))


if __name__ == "__main__":
    main()
