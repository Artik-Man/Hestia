#!/usr/bin/python3 -I
"""Export the applied topology and the most recent availability snapshot."""

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/hestia")
from profile import compile_profile, unique


def read(path: Path) -> dict:
    """Decode a local JSON file and reject duplicate keys."""
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def export(output: Path, base: Path = Path("/etc/hestia")) -> None:
    """Create a private, reference-only profile from verified installed settings without overwriting a file."""
    if (base / ".binding-pending").exists():
        raise ValueError("pending binding update requires recovery before export")
    source = base / "profile.json"
    if source.exists():
        raw = source.read_bytes()
        if (
            hashlib.sha256(raw).hexdigest()
            != (base / "profile-source.sha256").read_text().strip()
        ):
            raise ValueError("installed profile has changed since validation")
        profile = json.loads(raw, object_pairs_hook=unique)
    else:
        profile = {"version": 1, "mode": "bootstrap"}
    snapshot = read(base / "snapshot.json")
    if "healthy" in profile:
        expected = {k: profile[k] for k in ("groups", "lists", "healthy")}
        if "countryMap" in profile:
            expected["countryMap"] = profile["countryMap"]
        healthy = snapshot.get("healthy")
        known = {tag for group in profile["groups"] for tag in group["exits"]}
        if not isinstance(healthy, dict) or any(
            k not in known or type(v) is not bool for k, v in healthy.items()
        ):
            raise ValueError("snapshot contains invalid availability")
        profile["healthy"] = expected["healthy"] = healthy
        digest = hashlib.sha256((base / "sing-box.json").read_bytes()).hexdigest()
        matches_backend = (
            digest == (base / "profile-backend.sha256").read_text().strip()
        )
    else:
        expected, backend = compile_profile(profile, base)
        matches_backend = backend == read(base / "sing-box.json")
    if expected != snapshot or not matches_backend:
        raise ValueError(
            "installed settings differ from a supported deployment profile"
        )
    with tempfile.NamedTemporaryFile(
        dir=output.parent, prefix=".hestia-export-", delete=False
    ) as temp:
        path = Path(temp.name)
        try:
            temp.write((json.dumps(profile, indent=2) + "\n").encode())
            temp.flush()
            os.fsync(temp.fileno())
            os.link(path, output)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    if os.geteuid() or len(sys.argv) != 2:
        sys.exit("Usage: sudo hestia-export-config NEW_FILE.json")
    try:
        import fcntl

        with open("/run/hestia-install.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            export(Path(sys.argv[1]))
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"Export failed: {error}")
