"""Read one Keenetic Wi-Fi station interface and save only filtered status fields."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HOST = "root@192.168.1.1"
IDENTITY = "/Users/artikman/.ssh/hestia_keenetic"
KNOWN_HOSTS = "/Users/artikman/.ssh/known_hosts"
EXPECTED_NDMC_SHA256 = (
    "6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e"
)
DEFAULT_TARGET = "WifiMaster1/WifiStation0"
EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"
SSH_BASE = [
    "ssh",
    "-p",
    "222",
    "-i",
    IDENTITY,
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
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=2",
    HOST,
]
SAFE_IDS = {
    "WifiMaster0",
    "WifiMaster1",
    "WifiMaster1/WifiStation0",
    "GigabitEthernet1",
}
SAFE_TYPES = {"wifimaster", "wifistation", "accesspoint", "gigabitethernet"}


def run_remote(
    remote_command: str,
) -> tuple[subprocess.CompletedProcess[bytes], list[str]]:
    """Run one bounded SSH command with strict host-key verification and captured output."""
    argv = [*SSH_BASE, remote_command]
    result = subprocess.run(argv, capture_output=True, timeout=15, check=False)
    return result, argv


def parse_sha256(output: bytes) -> str | None:
    """Return the leading SHA-256 digest from a standard sha256sum line, if valid."""
    match = re.match(rb"^([0-9a-f]{64})\s+/bin/ndmc\s*$", output.strip())
    return match.group(1).decode("ascii") if match else None


def sanitize_output(output: bytes) -> list[dict[str, object]]:
    """Keep only allowlisted interface identity, state, priority, and target-match booleans."""
    fields: list[dict[str, object]] = []
    text = output.decode("utf-8", errors="replace")
    for line in text.splitlines():
        match = re.match(r"^(\s*)([A-Za-z][A-Za-z0-9_-]*):\s*(.*?)\s*$", line)
        if not match:
            continue
        indent, key, raw_value = match.groups()
        safe: object | None = None
        if key in {"id", "interface-name"} and raw_value in SAFE_IDS:
            safe = raw_value
        elif (
            key == "type"
            and raw_value.lower() in SAFE_TYPES
            or key in {"link", "state"}
            and raw_value.lower() in {"up", "down"}
        ):
            safe = raw_value.lower()
        elif key in {"connected", "defaultgw"} and raw_value.lower() in {
            "yes",
            "no",
            "true",
            "false",
        }:
            safe = raw_value.lower() in {"yes", "true"}
        elif (
            key == "index"
            and raw_value.isdecimal()
            and int(raw_value) < 16
            or key == "priority"
            and raw_value.isdecimal()
            and int(raw_value) <= 65535
        ):
            safe = int(raw_value)
        elif key == "description":
            safe = {"matches_iphone": raw_value == "iPhone"}
        elif key == "ssid":
            safe = {"matches_white_paper": raw_value == "White paper"}
        if safe is not None:
            fields.append({"key": key, "indent": len(indent), "value": safe})
    return fields


def write_evidence(record: dict[str, object], suffix: str = "station-status") -> Path:
    """Write one sanitized, uniquely named JSON record without retaining raw command output."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = EVIDENCE / f"attempt-{stamp}-{suffix}.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return path


def parse_target(argument: str | None) -> str:
    """Select one observed, allowlisted interface ID for a single read-only query."""
    target = argument or DEFAULT_TARGET
    if target not in {DEFAULT_TARGET, "GigabitEthernet1"}:
        raise ValueError("target is not allowlisted")
    return target


def main() -> int:
    """Verify the pinned ndmc binary, query one station once, and persist sanitized evidence."""
    target = parse_target(sys.argv[1] if len(sys.argv) > 1 else None)
    started = datetime.now(UTC).isoformat()
    hash_result, hash_argv = run_remote("sha256sum /bin/ndmc")
    observed_hash = parse_sha256(hash_result.stdout)
    if hash_result.returncode != 0 or observed_hash != EXPECTED_NDMC_SHA256:
        finished = datetime.now(UTC).isoformat()
        record: dict[str, object] = {
            "started_utc": started,
            "finished_utc": finished,
            "preflight_command": hash_argv,
            "preflight_exit_code": hash_result.returncode,
            "ndmc_sha256": observed_hash,
            "ndmc_sha256_matches": False,
            "raw_stdout_bytes": len(hash_result.stdout),
            "raw_stdout_sha256": hashlib.sha256(hash_result.stdout).hexdigest(),
            "raw_stderr_bytes": len(hash_result.stderr),
            "raw_stderr_sha256": hashlib.sha256(hash_result.stderr).hexdigest(),
            "raw_stdout_and_stderr_persisted": False,
        }
        path = write_evidence(record)
        print(
            json.dumps(
                {
                    "evidence": str(path),
                    "preflight_exit_code": hash_result.returncode,
                    "ndmc_sha256_matches": False,
                }
            )
        )
        return 2

    query_result, query_argv = run_remote(f"/bin/ndmc -c 'show interface {target}'")
    sanitized = sanitize_output(query_result.stdout)
    finished = datetime.now(UTC).isoformat()
    record: dict[str, object] = {
        "started_utc": started,
        "finished_utc": finished,
        "query_target": target,
        "target_is_candidate_derived_from_documented_naming": target == DEFAULT_TARGET,
        "hash_command": hash_argv,
        "hash_exit_code": hash_result.returncode,
        "ndmc_sha256": observed_hash,
        "query_command": query_argv,
        "query_exit_code": query_result.returncode,
        "raw_stdout_bytes": len(query_result.stdout),
        "raw_stdout_sha256": hashlib.sha256(query_result.stdout).hexdigest(),
        "raw_stderr_bytes": len(query_result.stderr),
        "raw_stderr_sha256": hashlib.sha256(query_result.stderr).hexdigest(),
        "sanitized_fields": sanitized,
        "raw_stdout_and_stderr_persisted": False,
    }
    path = write_evidence(record)
    print(
        json.dumps(
            {
                "evidence": str(path),
                "query_exit_code": query_result.returncode,
                "sanitized_field_count": len(sanitized),
            }
        )
    )
    return query_result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
