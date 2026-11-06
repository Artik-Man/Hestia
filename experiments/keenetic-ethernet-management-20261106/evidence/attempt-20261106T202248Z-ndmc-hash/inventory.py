#!/usr/bin/env python3
"""Run an allowlisted read-only NDMC inventory and persist sanitized evidence."""

from __future__ import annotations

import hashlib
import json
import base64
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


KNOWN_NDMC_SHA256 = "6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e"
KNOWN_HOST_FINGERPRINT = "SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo"
SSH_OPTIONS = [
    "ssh",
    "-p",
    "222",
    "-i",
    "/Users/artikman/.ssh/hestia_keenetic",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "UserKnownHostsFile=/Users/artikman/.ssh/known_hosts",
    "-o",
    "ConnectTimeout=7",
    "root@192.168.1.1",
]
ALLOWED_QUERIES = ["/bin/ndmc -c 'show interface'"]
ALLOWED_KEYS = {
    "id",
    "index",
    "interface",
    "interface name",
    "interface-name",
    "name",
    "type",
    "protocol",
    "description",
    "port",
    "port index",
    "interface index",
    "admin",
    "admin state",
    "link",
    "link state",
    "status",
    "state",
    "speed",
    "duplex",
    "ssid",
    "defaultgw",
    "priority",
}
KNOWN_LABELS = {"Home", "Solar (Moscow)", "Poppuri"}
KNOWN_SSID_TARGETS = {"iPhone", "White Paper"}
SAFE_STATE_VALUES = {
    "up",
    "down",
    "connected",
    "disconnected",
    "running",
    "stopped",
    "enabled",
    "disabled",
    "ready",
    "not ready",
    "active",
    "inactive",
    "yes",
    "no",
    "on",
    "off",
}
SAFE_TYPE_VALUES = {
    "bridge",
    "ethernet",
    "wifi",
    "wifi station",
    "wireguard",
    "zerotier",
    "sstp",
    "pppoe",
    "vlan",
    "tunnel",
    "gre",
    "ipip",
}


def utc_stamp() -> str:
    """Return a filesystem-safe UTC timestamp for a unique attempt directory."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_label(value: str) -> str | None:
    """Return an explicitly approved or interface-shaped label, if safe."""
    value = value.strip()
    if value in KNOWN_LABELS:
        return value
    port = re.fullmatch(r"(?:Port|port)\s*(0|1|2|3|4)", value)
    if port:
        return f"Port {port.group(1)}"
    if re.fullmatch(
        r"(?:Wireguard\d+|Sstp\d+|OpenVPN\d+|IKE[A-Za-z0-9_.-]*|"
        r"WifiMaster\d+|WifiStation\d+|GigabitEthernet\d+(?:/\d+)?)",
        value,
        flags=re.IGNORECASE,
    ):
        return value
    return None


def safe_field_value(key: str, value: str) -> str | int | bool | None:
    """Filter one allowlisted field value into a small safe domain."""
    value = value.strip()
    if key in {"name", "interface", "interface name", "interface-name"}:
        return safe_label(value)
    if key in {"port", "port index", "interface index"}:
        match = re.search(r"\b([0-4])\b", value)
        return int(match.group(1)) if match else None
    if key in {"state", "status", "admin", "admin state", "link", "link state"}:
        lowered = value.lower()
        return lowered if lowered in SAFE_STATE_VALUES else None
    if key == "speed":
        lowered = value.lower()
        speed_pattern = r"(?:auto|10|100|1000|10m|100m|1000m|1g|2\.5g|5g|10g)"
        speed_pattern += r"(?:\s*(?:mbps|gbps))?"
        return lowered if re.fullmatch(speed_pattern, lowered) else None
    if key == "duplex":
        lowered = value.lower()
        allowed_duplex = {"auto", "full", "half", "full duplex", "half duplex"}
        return lowered if lowered in allowed_duplex else None
    if key == "defaultgw":
        lowered = value.lower()
        bool_values = {"yes", "true", "on", "1", "no", "false", "off", "0"}
        if lowered not in bool_values:
            return None
        return lowered in {"yes", "true", "on", "1"}
    if key == "priority":
        return int(value) if re.fullmatch(r"\d{1,5}", value) else None
    if key in {"type", "protocol"}:
        lowered = value.lower()
        safe_type = lowered in SAFE_TYPE_VALUES or re.fullmatch(
            r"[a-z][a-z0-9_.+-]{0,31}", lowered
        )
        return lowered if safe_type else None
    if key == "id":
        return safe_label(value)
    if key == "index":
        return int(value) if re.fullmatch(r"\d{1,5}", value) else None
    if key == "description":
        label = safe_label(value)
        return label if label in KNOWN_LABELS or (label and label.startswith("Port ")) else None
    if key == "ssid":
        return value in KNOWN_SSID_TARGETS
    return None


def verify_known_host_pin() -> bool:
    """Confirm the matching known_hosts entry hashes to the previously pinned key."""
    result = subprocess.run(
        ["ssh-keygen", "-F", "[192.168.1.1]:222", "-f", "/Users/artikman/.ssh/known_hosts"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    for line in result.stdout.decode("ascii", errors="ignore").splitlines():
        if line.startswith("#"):
            continue
        fields = line.split()
        key_index = 2 if fields and fields[0].startswith("@") else 1
        if len(fields) <= key_index + 1:
            continue
        try:
            key_bytes = base64.b64decode(fields[key_index + 1], validate=True)
        except ValueError:
            continue
        digest = hashlib.sha256(key_bytes).digest()
        fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
        if fingerprint == KNOWN_HOST_FINGERPRINT:
            return True
    return False


def sanitize_output(raw: bytes) -> dict[str, object]:
    """Project interface blocks into safe IDs, exact labels, and allowlisted fields."""
    text = raw.decode("utf-8", errors="replace")
    records: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    def new_record() -> dict[str, object]:
        """Start an isolated block so fields from adjacent interfaces cannot merge."""
        record: dict[str, object] = {"block": len(records) + 1, "fields": []}
        records.append(record)
        return record

    for original_line in text.splitlines():
        line = original_line.strip()
        if not line:
            continue
        pattern = r"\s*[\"']?([A-Za-z][A-Za-z0-9 _.-]{0,40}?)[\"']?\s*([:=])\s*(.*?)\s*"
        match = re.fullmatch(pattern, original_line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group(1).strip().lower())
        key = key.replace("_", "-")
        value = match.group(3).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
            value = value[1:-1]
        if key == "id":
            current = new_record()
        elif key in {"interface-name", "interface", "interface name", "name"} and current is None:
            current = new_record()
        elif key == "description" and current is None:
            current = new_record()
        if current is None or key not in ALLOWED_KEYS:
            continue
        field: dict[str, object] = {
            "key": key,
            "indent": len(original_line) - len(original_line.lstrip()),
        }
        if key == "ssid":
            field["matches_iphone"] = value == "iPhone"
            field["matches_white_paper"] = value == "White Paper"
        else:
            field_value = safe_field_value(key, value)
            if field_value is None:
                continue
            field["value"] = field_value
        current["fields"].append(field)
    return {"records": records}


def run_remote(command: str) -> tuple[subprocess.CompletedProcess[bytes], str, bool]:
    """Run one fixed read-only command with a 30-second bound."""
    if command != "sha256sum /bin/ndmc" and command not in ALLOWED_QUERIES:
        raise ValueError("command is outside the explicit allowlist")
    argv = SSH_OPTIONS + [command]
    started = utc_stamp()
    try:
        result = subprocess.run(argv, capture_output=True, check=False, timeout=30)
        return result, started, False
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(
            argv,
            124,
            stdout=error.stdout or b"",
            stderr=error.stderr or b"",
        )
        return result, started, True


def write_attempt(
    evidence_root: Path,
    label: str,
    command: str,
    result: subprocess.CompletedProcess[bytes],
    started: str,
    source_bytes: bytes,
    timed_out: bool,
) -> Path:
    """Persist command identity, exit metadata, raw digest, and sanitized output."""
    attempt_dir = evidence_root / f"attempt-{started}-{label}"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    (attempt_dir / "inventory.py").write_bytes(source_bytes)
    stdout_digest = hashlib.sha256(result.stdout).hexdigest()
    stderr_digest = hashlib.sha256(result.stderr).hexdigest()
    if command == "sha256sum /bin/ndmc":
        match = re.fullmatch(rb"([0-9a-f]{64})\s+/bin/ndmc\s*", result.stdout)
        stdout_safe: dict[str, object] = {"ndmc_sha256": match.group(1).decode() if match else None}
    else:
        stdout_safe = sanitize_output(result.stdout)
    command_data = {
        "ssh_argv": SSH_OPTIONS + [command],
        "remote_command": command,
        "time_utc": started,
        "runner_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "timed_out": timed_out,
        "host_key_fingerprint_expected_sha256": KNOWN_HOST_FINGERPRINT,
        "host_key_pin_verified_before_ssh": True,
        "raw_stdout_bytes": len(result.stdout),
        "raw_stdout_sha256": stdout_digest,
        "raw_stderr_bytes": len(result.stderr),
        "raw_stderr_sha256": stderr_digest,
        "exit_code": result.returncode,
        "sanitized_stdout": stdout_safe,
    }
    (attempt_dir / "result-sanitized.json").write_text(
        json.dumps(command_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return attempt_dir


def main() -> int:
    """Verify the pinned executable hash, then run only the approved query."""
    evidence_root = Path(__file__).resolve().parents[1] / "evidence"
    source_bytes = Path(__file__).resolve().read_bytes()
    if not verify_known_host_pin():
        print("pinned_host_key_matches_known_hosts=false; stopped_without_ssh=true")
        return 3
    print("pinned_host_key_matches_known_hosts=true")
    hash_result, hash_time, hash_timeout = run_remote("sha256sum /bin/ndmc")
    hash_dir = write_attempt(
        evidence_root,
        "ndmc-hash",
        "sha256sum /bin/ndmc",
        hash_result,
        hash_time,
        source_bytes,
        hash_timeout,
    )
    print(f"ndmc_hash_attempt={hash_dir.name} exit_code={hash_result.returncode}")
    if hash_result.returncode != 0:
        return hash_result.returncode or 1
    hash_match = re.fullmatch(rb"([0-9a-f]{64})\s+/bin/ndmc\s*", hash_result.stdout)
    if not hash_match or hash_match.group(1).decode() != KNOWN_NDMC_SHA256:
        print("ndmc_hash_matches_expected=false; stopped_without_queries=true")
        return 2
    print("ndmc_hash_matches_expected=true")
    for index, command in enumerate(ALLOWED_QUERIES, start=1):
        source_bytes = Path(__file__).resolve().read_bytes()
        result, started, timed_out = run_remote(command)
        label = f"query-{index}"
        attempt_dir = write_attempt(
            evidence_root,
            label,
            command,
            result,
            started,
            source_bytes,
            timed_out,
        )
        print(f"{label}={command!r} attempt={attempt_dir.name} exit_code={result.returncode}")
        sanitized_path = attempt_dir / "result-sanitized.json"
        safe_json = json.loads(sanitized_path.read_text(encoding="utf-8"))["sanitized_stdout"]
        print(json.dumps(safe_json, ensure_ascii=False, sort_keys=True))
        if result.returncode != 0:
            print("stopped_after_failed_query=true")
            return result.returncode or 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
