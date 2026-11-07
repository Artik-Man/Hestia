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
PHYSICAL_PORT_ID_RE = re.compile(r"^GigabitEthernet[0-9]+/[0-9]+$")


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
            "sha256sum /bin/ndmc",
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


def schema_shape(value: Any) -> Any:
    """Return JSON shape counts without exposing interface names or field values."""
    if isinstance(value, dict):
        return {
            "type": "object",
            "member_count": len(value),
            "value_types": type_counts(value.values()),
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "item_count": len(value),
            "item_types": type_counts(value),
        }
    return {"type": type(value).__name__}


def type_counts(values: Any) -> dict[str, int]:
    """Count JSON value types without retaining object names or scalar contents."""
    counts: dict[str, int] = {}
    for value in values:
        name = type(value).__name__
        counts[name] = counts.get(name, 0) + 1
    return counts


def physical_port_summaries(value: Any) -> list[dict[str, Any]]:
    """Collect unique physical GigabitEthernet port records and a small status allowlist."""
    found: dict[str, dict[str, Any]] = {}
    if isinstance(value, dict):
        identifier = value.get("id")
        if (
            isinstance(identifier, str)
            and PHYSICAL_PORT_ID_RE.fullmatch(identifier)
            and value.get("type") == "Port"
        ):
            selected = {
                "id": identifier,
                "type": "Port",
            }
            for key in ("link", "state", "speed", "duplex"):
                item = value.get(key)
                if isinstance(item, (str, int, float, bool, type(None))):
                    selected[key] = item
            found[identifier] = selected
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                found.update(
                    {item["id"]: item for item in physical_port_summaries(child)}
                )
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                found.update(
                    {item["id"]: item for item in physical_port_summaries(child)}
                )
    return [found[key] for key in sorted(found)]


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
        summaries = physical_port_summaries(payload)
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
