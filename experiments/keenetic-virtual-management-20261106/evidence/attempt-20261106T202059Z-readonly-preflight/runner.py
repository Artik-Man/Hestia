#!/usr/bin/env python3
"""Run bounded, sanitized read-only state and management-route queries."""

from __future__ import annotations

import base64
import hashlib
import json
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
PROFILES = {
    "Solar (Moscow)": {"id": "Wireguard2", "type": "wireguard"},
    "Poppuri": {"id": "SSTP1", "type": "sstp"},
}
SAFE_STATES = {
    "up",
    "down",
    "connected",
    "disconnected",
    "connecting",
    "running",
    "stopped",
    "yes",
    "no",
    "true",
    "false",
    "on",
    "off",
}
ALLOWED_FIELDS = {"id", "type", "description", "state", "link", "status", "connected"}


def utc_stamp() -> str:
    """Return a filesystem-safe UTC timestamp used to identify this attempt."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def verify_known_host_pin() -> bool:
    """Verify the local known_hosts entry hashes to the previously pinned key."""
    result = subprocess.run(
        [
            "ssh-keygen",
            "-F",
            "[192.168.1.1]:222",
            "-f",
            "/Users/artikman/.ssh/known_hosts",
        ],
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
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip("=")
        if fingerprint == KNOWN_HOST_FINGERPRINT:
            return True
    return False


def run_ssh(command: str) -> tuple[int, bytes, bytes, bool]:
    """Run one fixed remote read-only command with a 25-second timeout."""
    try:
        result = subprocess.run(
            SSH_OPTIONS + [command],
            capture_output=True,
            check=False,
            timeout=25,
        )
        return result.returncode, result.stdout, result.stderr, False
    except subprocess.TimeoutExpired as error:
        return 124, error.stdout or b"", error.stderr or b"", True


def classify_stderr(raw: bytes) -> str:
    """Reduce stderr to a safe failure category without retaining its text."""
    text = raw.decode("utf-8", errors="replace").lower()
    if "operation not permitted" in text:
        return "sandbox_permission"
    if "host key verification failed" in text or "remote host identification has changed" in text:
        return "hostkey_mismatch"
    if "permission denied" in text:
        return "authentication"
    if "timed out" in text or "connection refused" in text or "no route to host" in text:
        return "network_unreachable"
    if "could not resolve" in text or "name or service not known" in text:
        return "name_resolution"
    return "other_suppressed" if raw else "empty"


def sanitize_profile(raw: bytes, label: str) -> dict[str, object]:
    """Keep only exact profile identity and normalized state/link fields."""
    expected = PROFILES[label]
    values: dict[str, str] = {}
    duplicates: list[str] = []
    for original_line in raw.decode("utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"\s*([A-Za-z][A-Za-z _.-]{0,30})\s*:\s*(.*?)\s*", original_line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group(1).strip().lower()).replace(" ", "_")
        if key not in ALLOWED_FIELDS:
            continue
        value = match.group(2).strip().strip("\"'")
        lowered = value.lower()
        if key in {"state", "link", "status", "connected"}:
            if lowered not in SAFE_STATES:
                continue
            safe_value = lowered
        elif key == "id":
            if value != expected["id"]:
                continue
            safe_value = value
        elif key == "type":
            if lowered != expected["type"]:
                continue
            safe_value = lowered
        elif key == "description":
            if value != label:
                continue
            safe_value = value
        else:
            continue
        if key in values and values[key] != safe_value:
            duplicates.append(key)
        values[key] = safe_value

    identity_ok = (
        values.get("id") == expected["id"]
        and values.get("type") == expected["type"]
        and values.get("description") == label
    )
    return {
        "label": label,
        "id": values.get("id"),
        "type": values.get("type"),
        "description_match": values.get("description") == label,
        "state": values.get("state"),
        "link": values.get("link"),
        "status": values.get("status"),
        "connected": values.get("connected"),
        "duplicate_conflict": sorted(set(duplicates)),
        "identity_verified": identity_ok,
        "readback_complete": identity_ok and "state" in values and "link" in values,
    }


def sanitize_control_help(raw: bytes, return_code: int) -> dict[str, object]:
    """Report whether read-only CLI help names both interface controls."""
    text = raw.decode("utf-8", errors="replace").lower()
    up_present = bool(re.search(r"(?m)^\s*up\s*(?:-|$)", text))
    down_present = bool(re.search(r"(?m)^\s*down\s*(?:-|$)", text))
    recognized = up_present and down_present
    return {
        "help_command_exit_code": return_code,
        "up_command_listed": up_present,
        "down_command_listed": down_present,
        "control_syntax_verified_by_device_help": recognized,
    }


def sanitize_route(raw: bytes) -> dict[str, object]:
    """Return only whether the SSH reply device matches either candidate VPN."""
    text = raw.decode("utf-8", errors="replace")
    device_match = re.search(r"\bdev\s+([A-Za-z0-9_.:/-]+)", text)
    if not device_match:
        return {"ssh_reply_route_lookup": "unknown", "via_candidate_profile": "unknown"}
    device = device_match.group(1)
    return {
        "ssh_reply_route_lookup": "found",
        "via_candidate_profile": device in {item["id"] for item in PROFILES.values()},
    }


def collect_local_route() -> dict[str, object]:
    """Confirm a local route to the Keenetic management IP without saving details."""
    try:
        result = subprocess.run(
            ["/sbin/route", "-n", "get", "192.168.1.1"],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"local_management_route_lookup": "unknown"}
    has_interface = bool(re.search(rb"(?m)^\s*interface:\s*\S+\s*$", result.stdout))
    return {
        "local_management_route_lookup": "found" if result.returncode == 0 and has_interface else "unknown"
    }


def write_evidence(
    evidence_dir: Path,
    started: str,
    runner_bytes: bytes,
    ndmc_hash: dict[str, object],
    profile_results: list[dict[str, object]],
    syntax_results: list[dict[str, object]],
    route_result: dict[str, object],
    local_route: dict[str, object],
) -> Path:
    """Persist sanitized metadata and hashes, never raw stdout/stderr."""
    attempt_dir = evidence_dir / f"attempt-{started}-readonly-preflight"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    (attempt_dir / "runner.py").write_bytes(runner_bytes)
    result = {
        "time_utc": started,
        "runner_sha256": hashlib.sha256(runner_bytes).hexdigest(),
        "host_key_fingerprint_expected_sha256": KNOWN_HOST_FINGERPRINT,
        "host_key_pin_verified_before_ssh": True,
        "ndmc_hash": ndmc_hash,
        "profiles": profile_results,
        "control_help": syntax_results,
        "management_route": {**local_route, **route_result},
        "raw_profile_and_route_output_persisted": False,
    }
    (attempt_dir / "result-sanitized.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return attempt_dir


def main() -> int:
    """Hash ndmc first, read only two allowlisted profiles and the SSH reply route."""
    runner_bytes = Path(__file__).resolve().read_bytes()
    if not verify_known_host_pin():
        print("host_key_pin_verified=false; ssh_started=false")
        return 3

    started = utc_stamp()
    ndmc_rc, ndmc_stdout, ndmc_stderr, ndmc_timeout = run_ssh("sha256sum /bin/ndmc")
    hash_match = re.fullmatch(rb"([0-9a-f]{64})\s+/bin/ndmc\s*", ndmc_stdout)
    observed_hash = hash_match.group(1).decode() if hash_match and ndmc_rc == 0 else None
    ndmc_hash: dict[str, object] = {
        "command": "sha256sum /bin/ndmc",
        "exit_code": ndmc_rc,
        "timed_out": ndmc_timeout,
        "stdout_bytes": len(ndmc_stdout),
        "stdout_sha256": hashlib.sha256(ndmc_stdout).hexdigest(),
        "stderr_bytes": len(ndmc_stderr),
        "stderr_sha256": hashlib.sha256(ndmc_stderr).hexdigest(),
        "stderr_reason": classify_stderr(ndmc_stderr),
        "sha256": observed_hash,
        "matches_pinned": observed_hash == KNOWN_NDMC_SHA256,
    }
    if ndmc_rc != 0 or observed_hash != KNOWN_NDMC_SHA256:
        evidence = write_evidence(
            Path(__file__).resolve().parents[1] / "evidence",
            started,
            runner_bytes,
            ndmc_hash,
            [],
            [],
            {"ssh_reply_route_lookup": "not_run"},
            {"local_management_route_lookup": "not_run"},
        )
        print(f"ndmc_hash_precondition_failed evidence={evidence}")
        return 2

    syntax_results = []
    for label, profile in PROFILES.items():
        command = f"/bin/ndmc -c 'interface {profile['id']} ?'"
        rc, stdout, stderr, timed_out = run_ssh(command)
        syntax_results.append(
            {
                "label": label,
                "id": profile["id"],
                **sanitize_control_help(stdout, rc),
                "command": command,
                "timed_out": timed_out,
                "stdout_bytes": len(stdout),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_bytes": len(stderr),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stderr_reason": classify_stderr(stderr),
            }
        )
        if rc != 0 or timed_out:
            break

    profile_results = []
    for label, profile in PROFILES.items():
        command = f"/bin/ndmc -c 'show interface {profile['id']}'"
        rc, stdout, stderr, timed_out = run_ssh(command)
        profile_results.append(
            {
                **sanitize_profile(stdout, label),
                "command": command,
                "exit_code": rc,
                "timed_out": timed_out,
                "stdout_bytes": len(stdout),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_bytes": len(stderr),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stderr_reason": classify_stderr(stderr),
            }
        )
        if rc != 0 or timed_out:
            break

    route_command = (
        "set -- ${SSH_CONNECTION-}; "
        "[ $# -ge 4 ] || exit 3; "
        "/opt/sbin/ip route get \"$1\" 2>/dev/null | "
        "awk '{for (i=1;i<=NF;i++) if ($i==\"dev\") {print \"dev \" $(i+1); exit}}'"
    )
    route_rc, route_stdout, route_stderr, route_timeout = run_ssh(route_command)
    route_result = sanitize_route(route_stdout) if route_rc == 0 and not route_timeout else {
        "ssh_reply_route_lookup": "unknown",
        "via_candidate_profile": "unknown",
    }
    route_result.update(
        {
            "command": "SSH client source route lookup; raw source address not retained",
            "exit_code": route_rc,
            "timed_out": route_timeout,
            "stdout_bytes": len(route_stdout),
            "stdout_sha256": hashlib.sha256(route_stdout).hexdigest(),
            "stderr_bytes": len(route_stderr),
            "stderr_sha256": hashlib.sha256(route_stderr).hexdigest(),
            "stderr_reason": classify_stderr(route_stderr),
        }
    )
    local_route = collect_local_route()
    evidence = write_evidence(
        Path(__file__).resolve().parents[1] / "evidence",
        started,
        runner_bytes,
        ndmc_hash,
        profile_results,
        syntax_results,
        route_result,
        local_route,
    )
    print(f"preflight_evidence={evidence}")
    print(json.dumps({"profiles": profile_results, "control_help": syntax_results, "management_route": {**local_route, **route_result}}, ensure_ascii=False))
    if any(not result.get("readback_complete") for result in profile_results):
        return 4
    if route_result.get("via_candidate_profile") is not False:
        return 5
    if local_route.get("local_management_route_lookup") != "found":
        return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
