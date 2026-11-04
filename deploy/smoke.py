#!/usr/bin/env python3
"""Read-only installation smoke check. Executed under an outer six-second timeout."""

import http.client
import json
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
    if live.read_bytes() != Path("/etc/hestia/sing-box.json").read_bytes():
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
    for group in config["groups"]:
        tag = group["id"]
        wanted = next(
            (
                exit_tag
                for exit_tag in group["exits"]
                if config["healthy"].get(exit_tag)
            ),
            "deny",
        )
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
