"""Run serialized, read-only Keenetic site surveys and save only filtered evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from read_wifi_status import (
    EXPECTED_NDMC_SHA256,
    SSH_BASE,
    parse_sha256,
    sanitize_output,
    write_evidence,
)

RADIOS = (("2.4GHz", "WifiMaster0"), ("5GHz", "WifiMaster1"))
TARGET_SSID = "White paper"


def run_remote(remote_command: str) -> tuple[subprocess.CompletedProcess[bytes], list[str]]:
    """Run one bounded remote command through the pinned SSH identity and host key."""
    argv = [*SSH_BASE, remote_command]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(
            argv,
            124,
            error.stdout or b"",
            error.stderr or b"",
        )
    return result, argv


def verified_ndmc_hash() -> tuple[str, list[str], int, bytes, bytes]:
    """Check the device ndmc SHA-256 and retain diagnostics only as lengths and hashes."""
    result, argv = run_remote("sha256sum /bin/ndmc")
    digest = parse_sha256(result.stdout)
    if result.returncode != 0 or digest != EXPECTED_NDMC_SHA256:
        raise RuntimeError(
            json.dumps(
                {
                    "hash_command": argv,
                    "hash_exit_code": result.returncode,
                    "ndmc_sha256_matches": False,
                    "stdout_bytes": len(result.stdout),
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_bytes": len(result.stderr),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                }
            )
        )
    return digest, argv, result.returncode, result.stdout, result.stderr


def parse_survey(output: bytes) -> dict[str, object]:
    """Count parseable survey rows and retain channel/quality only for the target SSID."""
    lines = output.decode("utf-8", errors="replace").splitlines()
    header: list[str] | None = None
    rows: list[dict[str, object]] = []
    unparsed = 0
    unparsed_structure: list[dict[str, object]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if "|" in stripped:
            columns = [part.strip().lower() for part in stripped.split("|")]
            if any(name.startswith(("ssid", "essid")) for name in columns) and any(
                name in {"ch", "channel"} for name in columns
            ):
                header = columns
                continue
            if set(stripped.replace("|", "").replace("=", "").strip()) <= {"-", " ", "_"}:
                continue
            if header is None:
                continue
            cells = [part.strip() for part in stripped.split("|")]
            if len(cells) != len(header):
                unparsed += 1
                unparsed_structure.append(line_structure(stripped))
                continue
            row = dict(zip(header, cells))
            name_key = next(name for name in header if name.startswith(("ssid", "essid")))
            channel = row.get("ch", row.get("channel", ""))
            quality = next(
                (row.get(name, "") for name in header if name in {"q", "quality", "signal"}),
                "",
            )
            ssid_value = row.get(name_key, "")
        else:
            match = re.match(
                r"^(.+?)\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(\d+)\s+\S+\s+(-?\d+)\s*$",
                stripped,
            )
            if match:
                ssid_value, _mac, channel, quality = match.groups()
                name_key = "ssid"
            elif any(token in stripped.lower() for token in ("ssid", "essid")) and "mac" in stripped.lower():
                continue
            elif set(stripped) <= {"-", "=", "_", " "}:
                continue
            else:
                unparsed += 1
                unparsed_structure.append(line_structure(stripped))
                continue
        if not channel.isdecimal() or not re.fullmatch(r"-?\d+(?:\s*dBm)?", quality, re.IGNORECASE):
            unparsed += 1
            unparsed_structure.append(line_structure(stripped))
            continue
        match_target = ssid_value == TARGET_SSID
        rows.append(
            {
                "target_ssid_match": match_target,
                "channel": int(channel),
                "quality": quality,
            }
        )
    complete = unparsed == 0 and (header is not None or bool(rows))
    matches = [{"channel": row["channel"], "quality": row["quality"]} for row in rows if row["target_ssid_match"]]
    return {
        "row_count": len(rows) if complete else None,
        "parsed_row_count": len(rows),
        "parse_complete": complete,
        "unparsed_nonempty_line_count": unparsed,
        "unparsed_line_structure": unparsed_structure[:20],
        "target_ssid_match_count": len(matches) if complete else None,
        "target_matches": matches if complete else None,
    }


def line_structure(line: str) -> dict[str, object]:
    """Describe an ambiguous line without preserving any network name or address."""
    return {
        "pipe_count": line.count("|"),
        "token_count": len(line.split()),
        "has_ssid_keyword": "ssid" in line.lower() or "essid" in line.lower(),
        "has_mac_keyword": "mac" in line.lower(),
        "has_mac_pattern": bool(re.search(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line)),
        "has_channel_keyword": "channel" in line.lower() or re.search(r"\bch\b", line.lower()) is not None,
        "separator_only": set(line) <= {"-", "=", "_", "|", " "},
    }


def query_interface_status(radio_id: str) -> tuple[dict[str, object], list[str]]:
    """Read and filter one radio's master/AP/station status without retaining raw output."""
    remote = f"/bin/ndmc -c 'show interface {radio_id}'"
    result, argv = run_remote(remote)
    record: dict[str, object] = {
            "command": argv,
            "exit_code": result.returncode,
            "stdout_bytes": len(result.stdout),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_bytes": len(result.stderr),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "sanitized_fields": sanitize_output(result.stdout),
    }
    if radio_id == "WifiMaster1":
        station_remote = "/bin/ndmc -c 'show interface WifiMaster1/WifiStation0'"
        station_result, station_argv = run_remote(station_remote)
        record["wisp_station_status"] = {
            "command": station_argv,
            "exit_code": station_result.returncode,
            "stdout_bytes": len(station_result.stdout),
            "stdout_sha256": hashlib.sha256(station_result.stdout).hexdigest(),
            "stderr_bytes": len(station_result.stderr),
            "stderr_sha256": hashlib.sha256(station_result.stderr).hexdigest(),
            "sanitized_fields": sanitize_output(station_result.stdout),
        }
    return record, argv


def scan_band(band: str, radio_id: str) -> dict[str, object]:
    """Capture status, run one documented site survey, capture status again, then filter."""
    started = datetime.now(timezone.utc).isoformat()
    try:
        ndmc_hash, hash_argv, hash_code, _, _ = verified_ndmc_hash()
    except RuntimeError as error:
        try:
            preflight_failure = json.loads(str(error))
        except json.JSONDecodeError:
            preflight_failure = {"failure": "hash preflight failed"}
        return {
            "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "band": band,
            "radio_id": radio_id,
            "scan_skipped": True,
            "preflight_failure": preflight_failure,
            "raw_output_persisted": False,
        }
    before, _ = query_interface_status(radio_id)
    before["observed_utc"] = datetime.now(timezone.utc).isoformat()
    if before["exit_code"] != 0 or before.get("wisp_station_status", {}).get("exit_code", 0) != 0:
        return {
            "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "band": band,
            "radio_id": radio_id,
            "ndmc_sha256": ndmc_hash,
            "hash_command": hash_argv,
            "hash_exit_code": hash_code,
            "scan_skipped": True,
            "before_status": before,
            "pre_status_query_failed": True,
            "raw_output_persisted": False,
        }

    remote = f"/bin/ndmc -c 'show site-survey {radio_id}'"
    survey_started = datetime.now(timezone.utc).isoformat()
    survey_result, survey_argv = run_remote(remote)
    survey_finished = datetime.now(timezone.utc).isoformat()
    summary = parse_survey(survey_result.stdout)

    after, _ = query_interface_status(radio_id)
    after["observed_utc"] = datetime.now(timezone.utc).isoformat()
    if after["exit_code"] != 0:
        summary["post_survey_status_read_failed"] = True

    return {
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "band": band,
        "radio_id": radio_id,
        "ndmc_sha256": ndmc_hash,
        "hash_command": hash_argv,
        "hash_exit_code": hash_code,
        "survey_command": survey_argv,
        "survey_started_utc": survey_started,
        "survey_finished_utc": survey_finished,
        "survey_exit_code": survey_result.returncode,
        "survey_stdout_bytes": len(survey_result.stdout),
        "survey_stdout_sha256": hashlib.sha256(survey_result.stdout).hexdigest(),
        "survey_stderr_bytes": len(survey_result.stderr),
        "survey_stderr_sha256": hashlib.sha256(survey_result.stderr).hexdigest(),
        "freshness_confirmed": False,
        "freshness_note": "The command returned survey data; no per-result timestamp was available.",
        "before_status": before,
        "survey_summary": summary,
        "after_status": after,
        "raw_stdout_and_stderr_persisted": False,
    }


def main() -> int:
    """Run the two bands serially and persist each band's sanitized result before continuing."""
    for band, radio_id in RADIOS:
        record = scan_band(band, radio_id)
        path = write_evidence(record, "site-survey")
        print(
            json.dumps(
                {
                    "band": band,
                    "evidence": str(path),
                    "survey_exit_code": record.get("survey_exit_code"),
                    "row_count": record.get("survey_summary", {}).get("row_count"),
                    "parse_complete": record.get("survey_summary", {}).get("parse_complete"),
                    "scan_skipped": record.get("scan_skipped", False),
                }
            )
        )
        if (
            record.get("scan_skipped")
            or record.get("survey_exit_code") != 0
            or record.get("after_status", {}).get("exit_code") != 0
            or record.get("after_status", {}).get("wisp_station_status", {}).get("exit_code", 0) != 0
        ):
            return 2
        time.sleep(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
