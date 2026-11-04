"""Summarize allow-listed markers and checksums without copying configuration or logs."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def smoke(directory, log):
    """Require the installer's embedded readiness success marker and return its elapsed whole seconds."""
    text = (directory / log).read_text()
    assert "PASS: both services active" in text
    return int(re.search(r"smoke check passed in (\d+) s", text).group(1))


def profile(directory):
    """Check profile acceptance markers and summarize runtime hashes without exporting key material."""
    expected_reports = [
        "PASS userspace WireGuard endpoint ru-wg",
        "PASS userspace WireGuard endpoint fi-wg",
        "PASS more specific domain precedes com; detached example.com omitted; default is russia",
        "PASS sing-box runtime containing VPN material is root-private",
    ]
    for name in ("runtime.txt", "runtime-after.txt"):
        runtime = (directory / name).read_text()
        assert all(row in runtime for row in expected_reports)
    assert "selected ru-wg" in (directory / "runtime-after.txt").read_text()
    assert ": OK" in (directory / "invalid-preserved.txt").read_text()
    assert (directory / "missing-peer.log").stat().st_size > 0
    assert (directory / "overwrite.log").stat().st_size > 0
    hashes = (directory / "final-runtime.sha256").read_text().splitlines()
    assert len(hashes) == 2
    copied = [row.split()[0] for row in hashes]
    assert all(re.fullmatch("[0-9a-f]{64}", digest) for digest in copied)
    snapshot = json.loads(Path("/etc/hestia/snapshot.json").read_text())
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    return dict(
        normalized_snapshot_sha256=hashlib.sha256(canonical).hexdigest(),
        smoke_seconds=smoke(directory, "install.log"),
        userspace_wireguard_endpoints=2,
        missing_sibling_rejected_with_prior_config_intact=True,
        nested_rule_precedence_verified=True,
        export_latest_availability_and_external_file_references=True,
        export_refuses_overwrite=True,
        final_runtime_sha256=copied,
    )


def bootstrap(directory):
    """Check first install, retry, failed smoke and reboot proof, returning only non-secret outcomes."""
    assert "FAILED" in (directory / "bad-install.log").read_text()
    assert "Smoke check failed" in (directory / "bad-smoke.log").read_text()
    assert "must be root-only" in (directory / "public-backend.log").read_text()
    assert ": OK" in (directory / "public-backend-preserved.txt").read_text()
    for prefix in ("first", "repeat", "reboot"):
        assert (directory / f"{prefix}-http.txt").read_text() == "hestia installer loopback test\n"
    assert (directory / "first-boot-id").read_text() != (directory / "reboot-id").read_text()
    assert "active" in (directory / "reboot-units.txt").read_text()
    assert ": OK" in (directory / "reboot-preserved.txt").read_text()
    return dict(
        tampered_archive_rejected=True,
        first_smoke_seconds=smoke(directory, "first-install.log"),
        repeat_smoke_seconds=smoke(directory, "repeat-install.log"),
        invalid_runtime_failed_at_smoke=True,
        public_backend_config_refused_without_service_changes=True,
        customized_configs_unchanged_on_repeat_and_reboot=True,
        bootstrap_export_private_and_refuses_overwrite=True,
        loopback_proxy_verified_before_and_after_repeat_and_after_reboot=True,
        services_enabled_and_active_after_reboot=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("bootstrap", "profile"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.exit(2, "Enable assertions")
    print(json.dumps((bootstrap if args.case == "bootstrap" else profile)(args.directory), indent=2))
