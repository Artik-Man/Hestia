"""Exercise installed list rebinding through two independent WireGuard peers on the dedicated VM."""

import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path("/etc/hestia")
SOURCE = Path("/var/tmp/hestia-binding-lab/profile.json")
API = "http://127.0.0.1:18438"
FILES = (
    "profile.json",
    "profile-source.sha256",
    "sing-box.json",
    "profile-backend.sha256",
    "snapshot.json",
)


def run(*args: str) -> str:
    """Run a required lab command with a timeout and return its stripped stdout."""
    return subprocess.check_output(args, text=True, timeout=90).strip()


def hashes() -> dict[str, str]:
    """Return checksums of the five managed files without disclosing tunnel credentials."""
    return {
        name: hashlib.sha256((BASE / name).read_bytes()).hexdigest() for name in FILES
    }


def binding(expected: str, target: str, code: int, **headers: str) -> None:
    """Request one binding update and assert its HTTP status and applied object."""
    body = {"listId": "target", "expectedGroup": expected, "group": target}
    request = urllib.request.Request(
        API + "/api/list-binding",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Origin": API, **headers},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=100) as response:
            status = response.status
            assert json.load(response) == {"listId": "target", "group": target}
    except urllib.error.HTTPError as error:
        status = error.code
    print(f"PUT {expected!r} -> {target!r} status={status}", flush=True)
    assert status == code, (code, status)


def traffic(phase: str, expected: str) -> None:
    """Open fresh SOCKS connections to both list masks and the independent control and verify replies."""
    for suffix, label in (
        ("bound", expected),
        ("second", expected),
        ("control", "alpha"),
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
        print(f"TCP {host} receiver={reply}", flush=True)
        assert reply == label, (host, label, reply)


def installed(group: str) -> None:
    """Verify the runtime, profile, snapshot and export agree while the installer input remains original."""
    with urllib.request.urlopen(API + "/api/groups-and-rules", timeout=5) as response:
        lists = json.load(response)["lists"]
        assert [entry["group"] for entry in lists] == [group, "group-alpha"]
        assert lists[0]["enabled"] == bool(group)
    profile = json.loads((BASE / "profile.json").read_text())
    snapshot = json.loads((BASE / "snapshot.json").read_text())
    assert snapshot["lists"] == profile["lists"]
    assert [entry["group"] for entry in profile["lists"]] == [group, "group-alpha"]
    assert profile["lists"][0]["masks"] == ["*.bound.lab.test", "*.second.lab.test"]
    assert json.loads(SOURCE.read_text())["lists"][0]["group"] == "group-alpha"
    digests = hashes()
    for file, checksum in (
        ("profile.json", "profile-source.sha256"),
        ("sing-box.json", "profile-backend.sha256"),
    ):
        assert digests[file] == (BASE / checksum).read_text().strip()
    export = SOURCE.parent / "verify-export.json"
    assert not export.exists()
    try:
        run("/usr/local/bin/hestia-export-config", str(export))
        assert json.loads(export.read_text()) == profile
    finally:
        export.unlink(missing_ok=True)
    assert not (BASE / ".binding-pending").exists()
    print(
        f"installed group={group!r} managed_hashes={json.dumps(digests, sort_keys=True)}",
        flush=True,
    )


def inject_failure() -> None:
    """Refuse only the alpha candidate at backend startup, then always remove the isolated test drop-in."""
    unit_dir = Path("/run/systemd/system/hestia-sing-box.service.d")
    unit_dir.mkdir(exist_ok=True)
    dropin = unit_dir / "qa-reject-alpha.conf"
    assert not dropin.exists()
    checker = Path("/run/hestia-binding-qa-reject.py")
    assert not checker.exists()
    run(
        "install",
        "-m",
        "0644",
        str(Path(__file__).with_name("reject-alpha.py")),
        str(checker),
    )
    with dropin.open("x") as output:
        output.write(f"[Service]\nExecStartPre=/usr/bin/python3 -I {checker}\n")
    try:
        run("systemctl", "daemon-reload")
        binding("group-beta", "group-alpha", 503)
        message = run(
            "journalctl",
            "-u",
            "hestia-sing-box.service",
            "--no-pager",
            "-g",
            "QA: refused candidate",
            "-n",
            "1",
        )
        assert "QA: refused candidate" in message, message
        print("fault: start rejected using candidate credential", flush=True)
    finally:
        dropin.unlink()
        checker.unlink()
        run("systemctl", "daemon-reload")


def crash_recovery() -> None:
    """Kill the in-flight helper after observing candidate egress and wait for autonomous rollback."""
    installed("")
    before = hashes()
    assert run("systemctl", "is-active", "hestia-binding-watch.path") == "active"
    unit_dir = Path("/run/systemd/system/hestia.service.d")
    unit_dir.mkdir(exist_ok=True)
    dropin = unit_dir / "qa-pause-candidate.conf"
    hook = Path("/run/hestia-binding-qa-wait.py")
    assert not dropin.exists() and not hook.exists()
    run(
        "install",
        "-m",
        "0644",
        str(Path(__file__).with_name("wait-beta.py")),
        str(hook),
    )
    dropin.write_text(f"[Service]\nExecStartPost=/usr/bin/python3 -I {hook}\n")
    try:
        run("systemctl", "daemon-reload")
        body = {"listId": "target", "expectedGroup": "", "group": "group-beta"}
        with subprocess.Popen(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "90",
                "--request",
                "PUT",
                "--header",
                "Content-Type: application/json",
                "--data",
                json.dumps(body),
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                API + "/api/list-binding",
            ],
            text=True,
            stdout=subprocess.PIPE,
        ) as client:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                result = subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "",
                        "--silent",
                        "--max-time",
                        "1",
                        "--socks5-hostname",
                        "127.0.0.1:1080",
                        "http://kill.bound.lab.test:18080/probe",
                    ],
                    stdout=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if result.stdout.strip() == "beta":
                    break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "candidate traffic did not reach beta before confirmation"
                )
            assert (BASE / ".binding-pending").is_dir()
            print(
                "TCP kill.bound.lab.test receiver=beta; journal=pending",
                flush=True,
            )
            helpers = []
            for path in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    argv = path.read_bytes().split(b"\x00")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if argv[:2] == [b"/usr/local/bin/hestia", b"-apply-binding"]:
                    helpers.append(int(path.parent.name))
            assert len(helpers) == 1, helpers
            os.kill(helpers[0], signal.SIGKILL)
            status, _ = client.communicate(timeout=15)
            print(f"SIGKILL helper; HTTP {status}", flush=True)
            assert status == "503", status
        started = time.monotonic()
        deadline = started + 75
        while (BASE / ".binding-pending").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not (BASE / ".binding-pending").exists(), (
            "watchdog failed to restore prior state"
        )
        assert hashes() == before
        installed("")
        traffic("kill-recovered", "alpha")
        print(
            f"watchdog recovery after helper exit: {time.monotonic() - started:.2f} s; no extra PUT or reboot",
            flush=True,
        )
    finally:
        dropin.unlink()
        hook.unlink()
        run("systemctl", "daemon-reload")


def main() -> None:
    """Test success, rejected requests, rollback and unbinding on the explicitly named fresh guest."""
    if (
        socket.gethostname().split(".")[0] != "lima-hestia-binding-test"
        or os.geteuid() != 0
    ):
        raise SystemExit("Only run as root on lima-hestia-binding-test")
    if sys.argv[1:] == ["--crash"]:
        crash_recovery()
        print("PASS", flush=True)
        return
    installed("group-alpha")
    traffic("before", "alpha")
    before = hashes()
    binding("group-alpha", "group-beta", 403, Origin="https://foreign.invalid")
    binding("group-alpha", "group-beta", 403, **{"Sec-Fetch-Site": "cross-site"})
    assert hashes() == before
    traffic("forbidden", "alpha")
    binding("group-alpha", "group-beta", 200)
    traffic("after", "beta")
    installed("group-beta")
    after = hashes()
    binding("group-alpha", "", 409)
    binding("group-beta", "unknown-group", 404)
    assert hashes() == after
    traffic("conflict", "beta")
    inject_failure()
    assert hashes() == after
    installed("group-beta")
    traffic("rollback", "beta")
    binding("group-beta", "", 200)
    installed("")
    traffic("unassigned", "alpha")
    print("PASS", flush=True)


if __name__ == "__main__":
    main()
