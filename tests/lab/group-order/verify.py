"""Check the installed order API and new SOCKS connections against three isolated WireGuard peers."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:18439"
BASE = Path("/etc/hestia")
FILES = (
    "profile.json",
    "profile-source.sha256",
    "snapshot.json",
    "sing-box.json",
    "profile-backend.sha256",
)
ALPHA = {"id": "group-alpha", "exits": ["exit-alpha", "exit-reserve"]}
RESERVE = {"id": "group-alpha", "exits": ["exit-reserve", "exit-alpha"]}
BETA = {"id": "group-beta", "exits": ["exit-beta"]}
INITIAL, EXIT_FIRST, GROUP_FIRST = [ALPHA, BETA], [RESERVE, BETA], [BETA, RESERVE]


def run(*argv: str) -> str:
    """Run one required command on the test guest, returning its bounded output or raising on failure."""
    return subprocess.check_output(argv, text=True, timeout=90).strip()


def hashes() -> dict[str, str]:
    """Hash the five managed files without revealing WireGuard secrets."""
    return {
        name: hashlib.sha256((BASE / name).read_bytes()).hexdigest() for name in FILES
    }


def apply(expected: list[dict], groups: list[dict], wanted: int) -> None:
    """Perform the documented compare-and-set over actual HTTP and verify the complete successful response."""
    request = urllib.request.Request(
        API + "/api/group-order",
        data=json.dumps({"expected": expected, "groups": groups}).encode(),
        headers={"Content-Type": "application/json", "Origin": API},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=105) as response:
            status = response.status
            assert json.load(response) == {"groups": groups}
    except urllib.error.HTTPError as error:
        status = error.code
    print(f"PUT group-order: HTTP {status}", flush=True)
    assert status == wanted, (status, wanted)


def state(groups: list[dict]) -> None:
    """Verify the confirmed profile, backend default route, snapshot and API view describe the same order."""
    profile = json.loads((BASE / "profile.json").read_text())
    source = json.loads(Path("/var/tmp/hestia-group-order/profile.json").read_text())
    snapshot = json.loads((BASE / "snapshot.json").read_text())
    config = json.loads((BASE / "sing-box.json").read_text())
    assert groups == profile["groups"] == snapshot["groups"]
    assert config["route"]["final"] == groups[0]["id"]
    assert snapshot["lists"] == profile["lists"] == source["lists"]
    assert snapshot["healthy"] == source["healthy"] and source["groups"] == INITIAL
    with urllib.request.urlopen(API + "/api/groups-and-rules", timeout=5) as response:
        observed = json.load(response)["groups"]
    assert [g["id"] for g in observed if g["isDefault"]] == [groups[0]["id"]]
    assert [
        {"id": g["id"], "exits": [e["id"] for e in g["exits"]]} for g in observed
    ] == groups
    print(
        "confirmed order="
        + json.dumps(groups, ensure_ascii=False)
        + " hashes="
        + json.dumps(hashes(), sort_keys=True),
        flush=True,
    )


def probe(phase: str, first: str, pinned_alpha: str) -> None:
    """Open new TCP connections for the default, equal suffix tie, and two pinned group controls."""
    for suffix, expected in (
        ("default", first),
        ("tie", first),
        ("alpha", pinned_alpha),
        ("beta", "beta"),
    ):
        host = f"{phase}.{suffix}.lab.test"
        reply = run(
            "curl",
            "--noproxy",
            "",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "8",
            "--socks5-hostname",
            "127.0.0.1:1080",
            f"http://{host}:18080/probe",
        )
        print(f"TCP {host} -> {reply}", flush=True)
        assert reply == expected, (host, expected, reply)


def refuse_new_default() -> None:
    """Reject startup for a candidate defaulting to alpha while allowing the previous beta generation."""
    directory = Path("/run/systemd/system/hestia-sing-box.service.d")
    directory.mkdir(exist_ok=True)
    dropin = directory / "order-test.conf"
    checker = Path("/run/hestia-order-test.py")
    assert not dropin.exists() and not checker.exists()
    run(
        "install",
        "-m",
        "0644",
        str(Path(__file__).with_name("reject-alpha.py")),
        str(checker),
    )
    try:
        with dropin.open("x") as output:
            output.write(f"[Service]\nExecStartPre=/usr/bin/python3 -I {checker}\n")
        run("systemctl", "daemon-reload")
        apply(GROUP_FIRST, INITIAL, 503)
        journal = run(
            "journalctl",
            "-u",
            "hestia-sing-box.service",
            "--no-pager",
            "-g",
            "QA: rejected candidate with group-alpha as default",
            "-n",
            "1",
        )
        assert "QA: rejected" in journal
        print("candidate start refusal confirmed by credential", flush=True)
    finally:
        dropin.unlink(missing_ok=True)
        checker.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")


def main() -> None:
    """Test real route changes, invalid order rejection, stale submissions and the browser's final topology."""
    if (
        socket.gethostname().split(".")[0] != "lima-hestia-binding-test"
        or os.geteuid() != 0
    ):
        raise SystemExit("Run only as root on lima-hestia-binding-test")
    if sys.argv[1:] == ["--after-browser"]:
        state(GROUP_FIRST)
        probe("browser", "beta", "reserve")
    else:
        state(INITIAL)
        probe("baseline", "alpha", "alpha")
        apply(INITIAL, EXIT_FIRST, 200)
        state(EXIT_FIRST)
        probe("exits", "reserve", "reserve")
        apply(EXIT_FIRST, GROUP_FIRST, 200)
        state(GROUP_FIRST)
        probe("groups", "beta", "reserve")
        saved = hashes()
        apply(INITIAL, EXIT_FIRST, 409)
        apply(GROUP_FIRST, [BETA], 422)
        apply(GROUP_FIRST, [{"id": "x" * 70000, "exits": []}], 413)
        apply(
            GROUP_FIRST,
            [
                {"id": "group-alpha", "exits": ["exit-alpha", "exit-beta"]},
                {"id": "group-beta", "exits": ["exit-reserve"]},
            ],
            422,
        )
        assert hashes() == saved
        state(GROUP_FIRST)
        probe("rejected", "beta", "reserve")
        refuse_new_default()
        assert hashes() == saved
        state(GROUP_FIRST)
        probe("rollback", "beta", "reserve")
        apply(GROUP_FIRST, INITIAL, 200)
        state(INITIAL)
        probe("restored", "alpha", "alpha")
    print("PASS", flush=True)


if __name__ == "__main__":
    main()
