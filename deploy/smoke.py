#!/usr/bin/env python3
"""Read-only installation smoke check. Executed under an outer six-second timeout."""

import http.client
import json
import os
import re
import stat
from datetime import datetime
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote


def run(*args):
    """Read one local diagnostic command within a one-second timeout."""
    return subprocess.check_output(
        args, text=True, stderr=subprocess.DEVNULL, timeout=1
    )


def fresh_awg_heartbeat(exit_id: str) -> bool:
    """Match the watcher's identity, age and file ownership checks on one runtime marker."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", exit_id):
        return False
    path = Path("/run/hestia-awg") / ("health.json." + exit_id)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o640
                    or info.st_uid != 0 or info.st_nlink != 1):
                return False
            raw = stream.read(4097)
        if len(raw) > 4096:
            return False
        record = json.loads(raw)
        if (not isinstance(record, dict) or set(record) - {"id", "status", "updatedAt", "activeUnderlay"}
                or not {"id","status","updatedAt"}.issubset(record)
                or ("activeUnderlay" in record and (not isinstance(record["activeUnderlay"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}",record["activeUnderlay"]) or record["activeUnderlay"] == exit_id))
                or record["id"] != exit_id or record["status"] != "ready"):
            return False
        timestamp = datetime.fromisoformat(record["updatedAt"].replace("Z", "+00:00"))
        return timestamp.tzinfo is not None and -1 <= time.time() - timestamp.timestamp() <= 5
    except (OSError, ValueError, AttributeError, TypeError, OverflowError):
        return False


def online_devices(backend: dict) -> dict[str, bool]:
    """Read current carrier for every bound direct exit from the verified running backend generation."""
    devices = {}
    for item in backend.get("outbounds", []):
        name = item.get("bind_interface")
        if item.get("type") != "direct" or not name or item["tag"] == "deny":
            continue
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", name):
            devices[item["tag"]] = False
            continue
        try:
            devices[item["tag"]] = (Path("/sys/class/net") / name / "carrier").read_text().strip() == "1"
        except OSError:
            devices[item["tag"]] = False
    return devices


def expected_target(config: dict, group: dict, devices: dict[str, bool] | None = None) -> str:
    """Return the first enabled exit with live carrier and a fresh tunnel heartbeat where applicable."""
    for exit_id in group["exits"]:
        if config["healthy"].get(exit_id) and (devices is None or devices.get(exit_id, True)) and (
            config.get("connectorKinds", {}).get(exit_id) != "awg" or fresh_awg_heartbeat(exit_id)
        ):
            return exit_id
    return "deny"


def quality_targets(config: dict, devices: dict[str, bool]) -> dict[str, str]:
    """Read only fresh controller confirmations for the current topology, retaining availability as a hard gate."""
    path = Path("/run/hestia-quality/report.json")
    try:
        report = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    captured = datetime.fromisoformat(report["capturedAt"].replace("Z", "+00:00"))
    if not 0 <= time.time() - captured.timestamp() <= 60:
        raise ValueError("quality controller report expired")
    observed = {group["id"]: group["connections"] for group in report["groups"]}
    selected = {}
    for group in config["groups"]:
        rows = observed.get(group["id"], [])
        if sorted(row["id"] for row in rows) != sorted(group["exits"]):
            raise ValueError("quality report and selector membership differ")
        active = [row["id"] for row in rows if row["active"]]
        if active:
            if len(active) != 1 or expected_target(config, {"exits": active}, devices) != active[0]:
                raise ValueError("quality controller selected an unavailable exit")
            selected[group["id"]] = active[0]
    return selected


def verify(*, fresh: bool = True):
    """Check active services, credential and selectors; after a restart also require fresh controller events."""
    for name in ("hestia", "hestia-sing-box", "hestia-binding-watch.path"):
        if run("systemctl", "is-active", name).strip() != "active":
            raise ValueError(f"{name} is not active")
    pid = run(
        "systemctl", "show", "-p", "MainPID", "--value", "hestia-sing-box"
    ).strip()
    sockets = run("ss", "-H", "-ltnp", "sport = :9090").splitlines()
    if (
        len(sockets) != 1
        or sockets[0].split()[3] != "127.0.0.1:9090"
        or f"pid={pid}," not in sockets[0]
    ):
        raise ValueError("127.0.0.1:9090 must belong to hestia-sing-box")

    # LoadCredential provides a per-invocation copy visible inside the service mount namespace.
    live = Path(
        f"/proc/{pid}/root/run/credentials/hestia-sing-box.service/sing-box.json"
    )
    generation = live.read_bytes()
    if generation != Path("/etc/hestia/sing-box.json").read_bytes():
        raise ValueError(
            "running backend credential differs from the installed configuration"
        )

    confirmed = {}
    if fresh:
        invocation = run(
            "systemctl", "show", "-p", "InvocationID", "--value", "hestia"
        ).strip()
        logs = run(
            "journalctl",
            "--no-pager",
            "-o",
            "cat",
            "_SYSTEMD_INVOCATION_ID=" + invocation,
        )
        for line in logs.splitlines():
            if line.startswith("{"):
                event = json.loads(line)
                confirmed[event["group"]] = event["selector_target"]

    config = json.loads(Path("/etc/hestia/snapshot.json").read_text())
    devices = online_devices(json.loads(generation))
    quality = quality_targets(config, devices)
    for group in config["groups"]:
        tag = group["id"]
        wanted = quality.get(tag, expected_target(config, group, devices))
        if fresh and confirmed.get(tag) != wanted:
            raise ValueError(f"controller has not confirmed {tag} -> {wanted}")
        api = http.client.HTTPConnection("127.0.0.1", 9090, timeout=0.5)
        try:
            api.request("GET", "/proxies/" + quote(tag, safe=""))
            resp = api.getresponse()
            if resp.status != 200:
                raise ValueError(f"selector {tag} did not respond")
            state = json.load(resp)
            if state["now"] != wanted or state["all"] != [*group["exits"], "deny"]:
                raise ValueError(
                    f"selector {tag} differs from the configured order or target"
                )
        finally:
            api.close()
    if not config["groups"]:
        raise ValueError("empty group list")


def main():
    """Retry read-only checks until success or the installation smoke deadline."""
    if sys.argv[1:] not in ([], ["--fresh"], ["--current"]):
        return 2
    deadline = time.monotonic() + 5
    while True:
        try:
            verify(fresh=sys.argv[1:] != ["--current"])
            print(
                "PASS: routing services and binding watch active, local API owner, loaded backend credential, controller confirmation and selector targets"
            )
            return 0
        except (
            OSError,
            ValueError,
            KeyError,
            subprocess.SubprocessError,
            http.client.HTTPException,
        ) as error:
            if time.monotonic() >= deadline:
                print(f"Smoke check failed: {error}", file=sys.stderr)
                return 1
        time.sleep(0.15)


if __name__ == "__main__":
    sys.exit(main())
