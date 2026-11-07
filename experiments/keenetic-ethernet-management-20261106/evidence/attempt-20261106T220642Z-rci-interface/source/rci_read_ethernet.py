#!/usr/bin/env python3
"""Read Ethernet interface metadata from the KN-1012 local RCI without saving raw JSON."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

ROUTER = "root@192.168.1.1"
SSH_PORT = "222"
SSH_KEY = "/Users/artikman/.ssh/hestia_keenetic"
KNOWN_HOSTS = "/Users/artikman/.ssh/known_hosts"
EXPECTED_HOST_KEY = "SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo"
EXPECTED_NDMC_SHA256 = "6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e"
TOKEN_FILE = "/Users/artikman/.config/hestia/keenetic-rci-token"
RCI_PATH = "/rci/show/interface"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ETHERNET_RE = re.compile(r"ethernet|gigabit|\beth[0-9]+\b", re.IGNORECASE)


def verify_known_host() -> str:
    """Verify the pinned SSH host key in known_hosts and return its fingerprint."""
    result = subprocess.run(
        ["ssh-keygen", "-F", "[192.168.1.1]:222", "-f", KNOWN_HOSTS],
        check=True,
        capture_output=True,
        text=True,
    )
    fingerprint = subprocess.run(
        ["ssh-keygen", "-lf", "-"],
        input=result.stdout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[1]
    if fingerprint != EXPECTED_HOST_KEY:
        raise RuntimeError("pinned_host_key_mismatch")
    return fingerprint


def verify_remote_binary() -> str:
    """Check the remote ndmc binary hash over pinned SSH before opening the RCI tunnel."""
    result = subprocess.run(
        [
            "ssh",
            "-p",
            SSH_PORT,
            "-i",
            SSH_KEY,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-o",
            "ConnectTimeout=7",
            ROUTER,
            "/bin/sha256sum",
            "/bin/ndmc",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=12,
    )
    digest = result.stdout.split()[0]
    if digest != EXPECTED_NDMC_SHA256:
        raise RuntimeError("remote_ndmc_hash_mismatch")
    return digest


def choose_local_port() -> int:
    """Reserve an ephemeral localhost port number for the short-lived SSH forward."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def start_tunnel(local_port: int) -> subprocess.Popen[bytes]:
    """Open a strict-host-key-checked local-only SSH forward to the router's RCI port."""
    process = subprocess.Popen(
        [
            "ssh",
            "-N",
            "-p",
            SSH_PORT,
            "-i",
            SSH_KEY,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-o",
            "ConnectTimeout=7",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-L",
            f"127.0.0.1:{local_port}:127.0.0.1:79",
            ROUTER,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("ssh_tunnel_start_failed")
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                return process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    process.wait(timeout=3)
    raise RuntimeError("ssh_tunnel_listener_timeout")


def read_response(local_port: int, token: str) -> tuple[int, str, bytes]:
    """Read the RCI endpoint with the local token and return status, type, and body in memory."""
    connection = http.client.HTTPConnection("127.0.0.1", local_port, timeout=10)
    try:
        connection.request(
            "GET",
            RCI_PATH,
            headers={"X-NDMA-TKN": token, "Accept": "application/json"},
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError("response_exceeds_limit")
        return response.status, response.getheader("Content-Type", ""), body
    finally:
        connection.close()


def schema_shape(value: Any, depth: int = 0) -> Any:
    """Return JSON types and field names only, without exposing values from unknown schema nodes."""
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": sorted(str(key) for key in value)[:40],
            "children": {
                str(key): schema_shape(child, depth + 1)
                for key, child in list(value.items())[:12]
            }
            if depth < 2
            else {},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "length": len(value),
            "first_item": schema_shape(value[0], depth + 1)
            if value and depth < 2
            else None,
        }
    return {"type": type(value).__name__}


def ethernet_summaries(value: Any, path: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Extract Ethernet-like interface identities and state fields while discarding addresses and secrets."""
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        scalar_text = " ".join(
            str(item)
            for key, item in value.items()
            if isinstance(item, (str, int, float, bool))
            and key.lower() in {"id", "name", "type", "kind", "interface", "ifname"}
        )
        contextual_text = " ".join((*path, scalar_text))
        if ETHERNET_RE.search(contextual_text):
            selected = {
                key: item
                for key, item in value.items()
                if key.lower()
                in {
                    "id",
                    "name",
                    "type",
                    "kind",
                    "interface",
                    "ifname",
                    "link",
                    "link_state",
                    "state",
                    "status",
                    "connected",
                    "online",
                    "present",
                }
                and isinstance(item, (str, int, float, bool, type(None)))
            }
            if selected:
                found.append(selected)
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                found.extend(ethernet_summaries(child, (*path, str(key))))
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                found.extend(ethernet_summaries(child, path))
    return found


def load_token() -> str:
    """Read the owner-provided token file without printing or persisting its value."""
    token = Path(TOKEN_FILE).read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("token_file_empty")
    return token


def main() -> int:
    """Run the single bounded RCI GET, emit sanitized metadata, and always close the SSH tunnel."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tunnel: subprocess.Popen[bytes] | None = None
    try:
        host_key = verify_known_host()
        binary_hash = verify_remote_binary()
        token = load_token()
        local_port = choose_local_port()
        tunnel = start_tunnel(local_port)
        status, content_type, body = read_response(local_port, token)
        response_hash = hashlib.sha256(body).hexdigest()
        print(
            json.dumps(
                {
                    "time_utc": started,
                    "request": {
                        "method": "GET",
                        "path": RCI_PATH,
                        "host": "127.0.0.1",
                        "port": 79,
                        "auth_header": "X-NDMA-TKN",
                        "token_value": "redacted",
                        "transport": "temporary SSH local-forward",
                    },
                    "host_key_fingerprint_sha256": host_key,
                    "ndmc_binary_sha256": binary_hash,
                    "response": {
                        "http_status": status,
                        "content_type": content_type,
                        "response_bytes": len(body),
                        "response_sha256": response_hash,
                    },
                    "raw_response_saved": False,
                },
                sort_keys=True,
            )
        )
        if status != 200:
            print(json.dumps({"result": "http_error_body_not_saved"}))
            return 2
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            print(json.dumps({"result": "response_not_json"}))
            return 3
        summaries = ethernet_summaries(payload)
        print(
            json.dumps(
                {
                    "result": "json_read",
                    "json_root_shape": schema_shape(payload),
                    "ethernet_interface_count": len(summaries),
                    "ethernet_interfaces": summaries,
                    "raw_response_saved": False,
                    "discarded_fields": ["addresses", "MACs", "DHCP", "Wi-Fi", "other interface data"],
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as error:  # Do not print exception payloads or response text.
        reason = str(error) if isinstance(error, RuntimeError) else "operation_failed"
        print(json.dumps({"result": "failed", "error_type": type(error).__name__, "reason": reason}))
        return 1
    finally:
        if tunnel is not None and tunnel.poll() is None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
