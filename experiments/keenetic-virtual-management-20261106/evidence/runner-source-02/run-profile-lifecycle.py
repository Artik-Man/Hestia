#!/usr/bin/env python3
"""Upload, hash-check, and run one approved bounded Keenetic profile cycle."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

KNOWN_HOST_FINGERPRINT = "SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo"
EXPECTED_SCRIPT_SHA256 = "ef5771e9cb7392146fdc98551d18d560cc6f3cd102e0b8c5dd257e32704c1e22"
SSH_BASE = [
    "ssh",
    "-T",
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
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    "root@192.168.1.1",
]
PROFILES = {
    "Solar (Moscow)": {"id": "Wireguard2", "slug": "solar"},
    "Poppuri": {"id": "SSTP1", "slug": "poppuri"},
}
SAFE_OUTPUT_PATTERNS = [
    re.compile(r"transition_command=(?:accepted|failed) target=up\Z"),
    re.compile(r"admin_state=(?:up|down|timeout target=(?:up|down))\Z"),
    re.compile(r"connection_state=(?:yes|no|timeout target=(?:yes|no))\Z"),
    re.compile(r"link_status=(?:up|down|running|stopped) connected=(?:yes|no) status=(?:up|down|connected|disconnected|connecting|active|inactive|none)\Z"),
    re.compile(r"restore_command=(?:accepted|failed)\Z"),
    re.compile(r"restore_status=failed watchdog_remains_armed=yes\Z"),
    re.compile(r"result=completed label=(?:Solar \(Moscow\)|Poppuri) id=(?:Wireguard2|SSTP1) type=(?:wireguard|sstp) initial_admin=down initial_connected=no\Z"),
    re.compile(r"result=refused reason=[a-z_]+\Z"),
]


def utc_stamp() -> str:
    """Return a UTC timestamp for this unique device attempt."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def verify_known_host_pin() -> bool:
    """Check the pinned host-key fingerprint before invoking SSH."""
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
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip("=")
        if fingerprint == KNOWN_HOST_FINGERPRINT:
            return True
    return False


def run_ssh(command: str, input_data: bytes | None, timeout: int) -> dict[str, object]:
    """Run one fixed SSH command and return output in memory with its exit code."""
    try:
        result = subprocess.run(
            SSH_BASE + [command],
            input=input_data,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "exit_code": 124,
            "stdout": error.stdout or b"",
            "stderr": error.stderr or b"",
            "timed_out": True,
        }


def stderr_reason(raw: bytes) -> str:
    """Reduce stderr to a non-sensitive error category."""
    text = raw.decode("utf-8", errors="replace").lower()
    if "operation not permitted" in text:
        return "sandbox_permission"
    if "host key verification failed" in text or "remote host identification has changed" in text:
        return "hostkey_mismatch"
    if "permission denied" in text:
        return "authentication"
    if "timed out" in text or "connection refused" in text or "no route to host" in text:
        return "network_unreachable"
    return "other_suppressed" if raw else "empty"


def safe_script_stdout(raw: bytes) -> tuple[list[str], bool]:
    """Retain only the remote script's exact allowlisted status lines."""
    lines = raw.decode("utf-8", errors="replace").splitlines()
    safe_lines = [line for line in lines if any(pattern.fullmatch(line) for pattern in SAFE_OUTPUT_PATTERNS)]
    return safe_lines, len(safe_lines) == len(lines)


def persist_attempt(
    evidence_root: Path,
    started: str,
    runner_bytes: bytes,
    label: str,
    commands: list[dict[str, object]],
    overall_result: str,
) -> Path:
    """Write sanitized commands, codes, hashes and allowlisted status output."""
    attempt_dir = evidence_root / f"attempt-{started}-lifecycle-{PROFILES[label]['slug']}"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    (attempt_dir / "runner.py").write_bytes(runner_bytes)
    record = {
        "time_utc": started,
        "runner_sha256": hashlib.sha256(runner_bytes).hexdigest(),
        "script_sha256_expected": EXPECTED_SCRIPT_SHA256,
        "host_key_fingerprint_expected_sha256": KNOWN_HOST_FINGERPRINT,
        "host_key_pin_verified_before_ssh": True,
        "label": label,
        "profile_id": PROFILES[label]["id"],
        "commands": commands,
        "result": overall_result,
        "raw_stdout_or_stderr_persisted": False,
    }
    (attempt_dir / "result-sanitized.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return attempt_dir


def main() -> int:
    """Upload one pinned script, verify it on device, run one profile, and clean staging."""
    if len(sys.argv) != 2 or sys.argv[1] not in PROFILES:
        print("usage=run-profile-lifecycle.py '<Solar (Moscow)|Poppuri>'")
        return 2
    label = sys.argv[1]
    profile = PROFILES[label]
    source_path = Path(__file__).resolve().with_name("profile-lifecycle-remote.sh")
    runner_bytes = Path(__file__).resolve().read_bytes()
    source_bytes = source_path.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != EXPECTED_SCRIPT_SHA256:
        print("source_hash_matches_snapshot=false; ssh_started=false")
        return 3
    if not verify_known_host_pin():
        print("host_key_pin_verified=false; ssh_started=false")
        return 4

    started = utc_stamp()
    stage = f"/tmp/hestia-vpn-lifecycle-{profile['slug']}-{started}"
    remote_file = f"{stage}/profile-lifecycle-remote.sh"
    commands: list[dict[str, object]] = []
    overall = "refused"

    upload_command = f"umask 077; mkdir -m 700 '{stage}' && cat > '{remote_file}'"
    upload = run_ssh(upload_command, source_bytes, 20)
    upload_stdout = upload["stdout"]
    upload_stderr = upload["stderr"]
    commands.append(
        {
            "phase": "upload",
            "command": upload_command,
            "exit_code": upload["exit_code"],
            "timed_out": upload["timed_out"],
            "stdout_bytes": len(upload_stdout),
            "stdout_sha256": hashlib.sha256(upload_stdout).hexdigest(),
            "stderr_bytes": len(upload_stderr),
            "stderr_sha256": hashlib.sha256(upload_stderr).hexdigest(),
            "stderr_reason": stderr_reason(upload_stderr),
        }
    )
    if upload["exit_code"] != 0 or upload["timed_out"]:
        evidence = persist_attempt(Path(__file__).resolve().parents[1] / "evidence", started, runner_bytes, label, commands, overall)
        print(f"upload_failed evidence={evidence}")
        return int(upload["exit_code"])

    hash_command = f"sha256sum '{remote_file}'"
    remote_hash = run_ssh(hash_command, None, 15)
    hash_output = remote_hash["stdout"]
    match = re.fullmatch(rb"([0-9a-f]{64})\s+/tmp/[^\s]+/profile-lifecycle-remote\.sh\s*", hash_output)
    observed_hash = match.group(1).decode() if match and remote_hash["exit_code"] == 0 else None
    commands.append(
        {
            "phase": "remote_source_hash",
            "command": hash_command,
            "exit_code": remote_hash["exit_code"],
            "timed_out": remote_hash["timed_out"],
            "sha256": observed_hash,
            "matches_local_source": observed_hash == source_hash,
            "stdout_bytes": len(hash_output),
            "stdout_sha256": hashlib.sha256(hash_output).hexdigest(),
            "stderr_bytes": len(remote_hash["stderr"]),
            "stderr_sha256": hashlib.sha256(remote_hash["stderr"]).hexdigest(),
            "stderr_reason": stderr_reason(remote_hash["stderr"]),
        }
    )
    if remote_hash["exit_code"] == 0 and observed_hash == source_hash:
        run_command = f"/bin/sh '{remote_file}' '{label}' down no"
        remote_run = run_ssh(run_command, None, 180)
        safe_lines, stdout_is_safe = safe_script_stdout(remote_run["stdout"])
        commands.append(
            {
                "phase": "lifecycle",
                "command": run_command,
                "exit_code": remote_run["exit_code"],
                "timed_out": remote_run["timed_out"],
                "stdout_allowlisted_lines": safe_lines,
                "stdout_all_lines_allowlisted": stdout_is_safe,
                "stdout_bytes": len(remote_run["stdout"]),
                "stdout_sha256": hashlib.sha256(remote_run["stdout"]).hexdigest(),
                "stderr_bytes": len(remote_run["stderr"]),
                "stderr_sha256": hashlib.sha256(remote_run["stderr"]).hexdigest(),
                "stderr_reason": stderr_reason(remote_run["stderr"]),
            }
        )
        completed_line = any(
            line.startswith(f"result=completed label={label} id={profile['id']} ")
            for line in safe_lines
        )
        restore_verified = (
            "restore_command=accepted" in safe_lines
            and "admin_state=down" in safe_lines
            and "connection_state=no" in safe_lines
        )
        overall = (
            "completed"
            if remote_run["exit_code"] == 0 and stdout_is_safe and completed_line and restore_verified
            else "failed_or_incomplete"
        )
    else:
        overall = "refused_remote_hash_mismatch"

    cleanup_command = f"rm -f '{remote_file}' && rmdir '{stage}'"
    cleanup = run_ssh(cleanup_command, None, 15)
    commands.append(
        {
            "phase": "staging_cleanup",
            "command": cleanup_command,
            "exit_code": cleanup["exit_code"],
            "timed_out": cleanup["timed_out"],
            "stdout_bytes": len(cleanup["stdout"]),
            "stdout_sha256": hashlib.sha256(cleanup["stdout"]).hexdigest(),
            "stderr_bytes": len(cleanup["stderr"]),
            "stderr_sha256": hashlib.sha256(cleanup["stderr"]).hexdigest(),
            "stderr_reason": stderr_reason(cleanup["stderr"]),
        }
    )
    if cleanup["exit_code"] != 0 or cleanup["timed_out"]:
        overall = "completed_with_staging_cleanup_error" if overall == "completed" else "cleanup_error"

    evidence = persist_attempt(Path(__file__).resolve().parents[1] / "evidence", started, runner_bytes, label, commands, overall)
    print(f"lifecycle_evidence={evidence}")
    print(json.dumps({"label": label, "result": overall, "commands": commands}, ensure_ascii=False))
    return 0 if overall == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
