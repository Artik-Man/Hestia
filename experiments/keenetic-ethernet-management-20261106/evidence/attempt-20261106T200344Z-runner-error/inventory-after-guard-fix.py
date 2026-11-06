#!/usr/bin/env python3
"""Run an allowlisted read-only NDMC inventory and persist sanitized evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
KNOWN_NDMC_SHA256 = "6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e"
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
ALLOWED_QUERIES = [
    "/bin/ndmc -c 'show interface'",
    "/bin/ndmc -c 'show interface Home'",
]
ALLOWED_KEYS = {
    "interface",
    "interface name",
    "name",
    "type",
    "protocol",
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
}
KNOWN_LABELS = {"Home", "Solar (Moscow)", "Poppuri"}
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


def utc_stamp() -> str:
    """Return a filesystem-safe UTC timestamp for a unique attempt directory."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_label(value: str) -> str | None:
    """Return an explicitly approved or interface-shaped label, if safe."""
    value = value.strip()
    if value in KNOWN_LABELS:
        return value
    if re.fullmatch(r"(?:Port|port)\s+(?:1|4)", value):
        return f"Port {value.split()[-1]}"
    if re.fullmatch(r"(?:eth|en|br|wlan|wlp|WifiMaster|GigabitEthernet)[A-Za-z0-9_./-]{0,24}", value):
        return value
    return None


def safe_field_value(key: str, value: str) -> str | int | None:
    """Filter one allowlisted field value into a small safe domain."""
    value = value.strip()
    if key in {"name", "interface", "interface name"}:
        return safe_label(value)
    if key in {"port", "port index", "interface index"}:
        match = re.search(r"\b([14])\b", value)
        return int(match.group(1)) if match else None
    if key in {"state", "status", "admin", "admin state", "link", "link state"}:
        lowered = value.lower()
        return lowered if lowered in SAFE_STATE_VALUES else None
    if key == "speed":
        lowered = value.lower()
        return lowered if re.fullmatch(r"(?:auto|10|100|1000|10m|100m|1000m|1g|2\.5g|5g|10g)(?:\s*(?:mbps|gbps))?", lowered) else None
    if key == "duplex":
        lowered = value.lower()
        return lowered if lowered in {"auto", "full", "half", "full duplex", "half duplex"} else None
    if key in {"type", "protocol"}:
        return value.lower() if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]{0,23}", value) else None
    return None


def sanitize_output(raw: bytes) -> dict[str, object]:
    """Extract only approved interface labels and selected operational fields."""
    text = raw.decode("utf-8", errors="replace")
    records: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for original_line in text.splitlines():
        line = original_line.strip()
        if not line:
            continue
        header = re.fullmatch(r"(?:Interface\s+)?([^:=]{1,40})", line, flags=re.IGNORECASE)
        if header:
            label = safe_label(header.group(1))
            if label:
                current = {"label": label}
                records.append(current)
                continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z _-]{0,30})\s*[:=]\s*(.*?)\s*", line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group(1).strip().lower())
        if key not in ALLOWED_KEYS:
            continue
        field_value = safe_field_value(key, match.group(2))
        if field_value is None:
            continue
        if key in {"name", "interface", "interface name"}:
            current = {"label": field_value}
            records.append(current)
        else:
            if current is None:
                current = {}
                records.append(current)
            current[key] = field_value
    compact = [record for record in records if record]
    return {"records": compact}


def run_remote(command: str) -> tuple[subprocess.CompletedProcess[bytes], str]:
    """Run one fixed read-only command and return captured bytes and timestamp."""
    if command != "sha256sum /bin/ndmc" and command not in ALLOWED_QUERIES:
        raise ValueError("command is outside the explicit allowlist")
    argv = SSH_OPTIONS + [command]
    started = utc_stamp()
    result = subprocess.run(argv, capture_output=True, check=False)
    return result, started


def write_attempt(
    evidence_root: Path,
    label: str,
    command: str,
    result: subprocess.CompletedProcess[bytes],
    started: str,
) -> Path:
    """Persist command identity, exit metadata, raw digest, and sanitized output."""
    attempt_dir = evidence_root / f"attempt-{started}-{label}"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    stdout_digest = hashlib.sha256(result.stdout).hexdigest()
    stderr_digest = hashlib.sha256(result.stderr).hexdigest()
    if command == "sha256sum /bin/ndmc":
        match = re.fullmatch(rb"([0-9a-f]{64})\s+/bin/ndmc\s*", result.stdout)
        stdout_safe: dict[str, object] = {"ndmc_sha256": match.group(1).decode() if match else None}
    else:
        stdout_safe = sanitize_output(result.stdout)
    command_data = {
        "command": "ssh -p 222 -i /Users/artikman/.ssh/hestia_keenetic -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/Users/artikman/.ssh/known_hosts -o ConnectTimeout=7 root@192.168.1.1 "
        + json.dumps(command),
        "time_utc": started,
        "host_key_fingerprint_expected_sha256": "SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo",
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
    """Verify the pinned executable hash, then run only the approved query pair."""
    evidence_root = Path(__file__).resolve().parent
    hash_result, hash_time = run_remote("sha256sum /bin/ndmc")
    hash_dir = write_attempt(evidence_root, "ndmc-hash", "sha256sum /bin/ndmc", hash_result, hash_time)
    print(f"ndmc_hash_attempt={hash_dir.name} exit_code={hash_result.returncode}")
    if hash_result.returncode != 0:
        return hash_result.returncode or 1
    hash_match = re.fullmatch(rb"([0-9a-f]{64})\s+/bin/ndmc\s*", hash_result.stdout)
    if not hash_match or hash_match.group(1).decode() != KNOWN_NDMC_SHA256:
        print("ndmc_hash_matches_expected=false; stopped_without_queries=true")
        return 2
    print("ndmc_hash_matches_expected=true")
    for index, command in enumerate(ALLOWED_QUERIES, start=1):
        result, started = run_remote(command)
        label = f"query-{index}"
        attempt_dir = write_attempt(evidence_root, label, command, result, started)
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
