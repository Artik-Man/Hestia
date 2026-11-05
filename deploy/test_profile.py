"""Run with python3 -m unittest discover -s deploy."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from profile import (
    compile_profile,
    export_paths,
    managed_profile,
    semantically_equal_backend,
    stage_binding,
    stage_create_group,
    stage_delete_group,
    stage_move_exit,
    stage_order,
    stage_rename_group,
)
from unittest.mock import patch

from smoke import expected_target

EXAMPLES = Path(__file__).parent / "examples"


class ProfileTests(unittest.TestCase):
    """Exercise profile compilation against isolated synthetic VPN configuration files."""

    def setUp(self):
        """Copy the example inputs into a fresh temporary directory for each case."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        for path in EXAMPLES.iterdir():
            shutil.copyfile(path, self.base / path.name)
        self.profile = json.loads((self.base / "stand.json").read_text())

    def compile(self):
        """Compile the current test profile using only its temporary directory for secrets."""
        return compile_profile(self.profile, self.base)

    def test_dns_path_export_scopes_credentials_and_generation(self):
        """Export per-exit resolver addresses, confinement and generation without copying private VPN keys."""
        _, backend = self.compile()
        source = self.base / "sing-box.json"
        source.write_text(json.dumps(backend))
        stamp = source.stat()
        with (
            patch("profile.os.setgroups") as groups,
            patch("profile.os.setgid") as gid,
            patch("profile.os.setuid") as uid,
        ):
            export_paths(backend, self.base, stamp)
        groups.assert_called_once_with([])
        gid.assert_called_once_with(self.base.stat().st_gid)
        uid.assert_called_once_with(self.base.stat().st_uid)
        published = self.base / "paths.json"
        self.assertEqual(published.stat().st_mode & 0o777, 0o600)
        encoded = published.read_text()
        report = json.loads(encoded)
        self.assertEqual(report["inode"], stamp.st_ino)
        self.assertEqual(report["modified"], stamp.st_mtime_ns)
        for endpoint in backend["endpoints"]:
            self.assertNotIn(endpoint["private_key"], encoded)
            relay = next(
                path for path in report["paths"] if path["id"] == endpoint["tag"]
            )
            self.assertTrue(relay["socksAddress"].startswith("127.0.0.1:"))
            self.assertTrue(relay["socksPassword"])
            dns = next(
                server
                for server in backend["dns"]["servers"]
                if server.get("detour") == endpoint["tag"]
            )
            self.assertEqual(report["resolvers"][endpoint["tag"]], dns["server"])
        self.assertNotIn("deny", [path["id"] for path in report["paths"]])

    def test_mask_rejects_non_ascii_before_lowercasing(self):
        """Reject non-ASCII masks even when lowercase conversion produces a valid ASCII label."""
        self.profile["lists"][0]["masks"] = ["*.K.example"]
        with self.assertRaisesRegex(ValueError, "ASCII"):
            self.compile()

    def test_domain_exceptions_and_unassigned_list(self):
        """Verify mask precedence, disabled lists, default group and isolated overlapping addresses."""
        snapshot, engine = self.compile()
        self.assertEqual(snapshot["lists"][-1]["group"], "")
        routes = engine["route"]
        self.assertEqual(routes["final"], "russia")
        self.assertEqual(
            [(r["domain_suffix"], r["outbound"]) for r in routes["rules"] if "domain_suffix" in r],
            [("deepseek.com", "russia"), ("com", "finland")],
        )
        self.assertEqual(
            engine["endpoints"][0]["address"], engine["endpoints"][1]["address"]
        )

    def test_order_rebuilds_routes_and_selectors_without_vpn_inputs(self):
        """A reorder changes the default and tie winner while preserving all memberships, rules and secrets."""
        self.profile["interfaces"].append(
            dict(self.profile["interfaces"][1], id="fi-backup")
        )
        self.profile["groups"][1]["exits"].append("fi-backup")
        self.profile["lists"].append(
            {"id": "tie", "group": "russia", "masks": ["*.com"]}
        )
        snapshot, old = self.compile()
        snapshot["healthy"] = {"fi-backup": True}
        for filename, obj, digest in (
            ("profile.json", self.profile, "profile-source.sha256"),
            ("sing-box.json", old, "profile-backend.sha256"),
            ("snapshot.json", snapshot, None),
        ):
            raw = json.dumps(obj).encode()
            (self.base / filename).write_bytes(raw)
            if digest:
                (self.base / digest).write_text(hashlib.sha256(raw).hexdigest())
        for secret in self.base.glob("*.conf"):
            secret.unlink()
        stage = self.base / "stage"
        stage.mkdir()
        groups = [
            {"id": "finland", "exits": ["fi-backup", "fi-wg"]},
            self.profile["groups"][0],
        ]
        stage_order(self.base, stage, groups)
        active = json.loads((stage / "snapshot.json").read_bytes())
        self.assertEqual(active, dict(snapshot, groups=groups))
        candidate = json.loads((stage / "sing-box.json").read_bytes())
        self.assertEqual(candidate["endpoints"], old["endpoints"])
        self.assertEqual(candidate["dns"], old["dns"])
        self.assertEqual(candidate["route"]["final"], "finland")
        self.assertEqual(
            [(r["domain_suffix"], r["outbound"]) for r in candidate["route"]["rules"] if "domain_suffix" in r],
            [("deepseek.com", "russia"), ("com", "finland"), ("com", "russia")],
        )
        self.assertEqual(
            candidate["outbounds"][1]["outbounds"], ["fi-backup", "fi-wg", "deny"]
        )
        self.assertEqual(
            json.loads((stage / "profile.json").read_bytes()),
            dict(self.profile, groups=groups),
        )

        moved = self.base / "moved"
        moved.mkdir()
        stage_move_exit(stage, moved, "ru-wg", "russia", "finland", 2)
        _, moved_snapshot, moved_backend = managed_profile(moved)
        self.assertEqual(moved_snapshot["groups"][0]["exits"], ["fi-backup", "ru-wg", "fi-wg"])
        self.assertEqual(moved_backend["outbounds"][1]["outbounds"], ["fi-backup", "ru-wg", "fi-wg", "deny"])
        self.assertEqual(moved_backend["route"], candidate["route"])

    def test_reject_missing_traversal_symlink_inline_keys(self):
        """Reject invalid file references and attempts to place secret material directly in the profile."""
        interface = self.profile["interfaces"][0]
        (self.base / "alias").symlink_to(self.base / "ru-wg.conf")
        for ref in ("missing", "../ru-wg.conf", "/etc/passwd", "alias"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                interface["config_file"] = ref
                self.compile()
        interface["config_file"] = "ru-wg.conf"
        interface["private_key"] = "example"
        with self.assertRaises(ValueError):
            self.compile()

    def test_separate_key_file_and_unsafe_hooks(self):
        """Accept a separate private key while refusing executable hooks in a VPN file."""
        interface = self.profile["interfaces"][0]
        path = self.base / interface["config_file"]
        lines = path.read_text().splitlines()
        key = next(s for s in lines if s.startswith("PrivateKey"))
        path.write_text("\n".join(s for s in lines if s != key))
        interface["private_key_file"] = "ru.key"
        (self.base / "ru.key").write_text(key.split(" = ")[1])
        self.compile()
        path.write_text(
            path.read_text().replace("[Peer]", "PostUp = touch /tmp/unsafe\n[Peer]")
        )
        with self.assertRaises(ValueError):
            self.compile()

    def test_amneziawg_connector_compiles_marked_ipv4_exit_and_dns(self):
        """Compile a metadata-only AWG exit while keeping its private config out of sing-box output."""
        connector = "12345678-1234-4abc-8abc-123456789abc"
        directory = self.base / "awg" / connector
        directory.mkdir(parents=True, mode=0o700)
        metadata = {
            "id": connector,
            "name": "Офис № 2",
            "group": "finland",
            "priority": 2,
            "status": "configured",
            "ipv6Blocked": False,
            "type": "amneziawg",
            "ipv4Address": "10.66.66.2/32",
            "dnsIPv4": "1.1.1.1",
        }
        (directory / "metadata.json").write_text(json.dumps(metadata))
        (directory / "metadata.json").chmod(0o600)
        (directory / "profile.conf").write_text("PrivateKey = secret-marker\n")
        (directory / "profile.conf").chmod(0o600)
        self.profile["version"] = 2
        self.profile["connectors"] = [
            {
                "id": connector,
                "name": "Офис № 2",
                "type": "amneziawg",
                "group": "finland",
                "priority": 2,
                "ipv6Blocked": False,
                "status": "configured",
            }
        ]
        self.profile["groups"][1]["exits"].append(connector)
        snapshot, engine = self.compile()
        self.assertEqual(snapshot["groups"][1]["exits"], ["fi-wg", connector])
        self.assertEqual(snapshot["connectorKinds"], {connector: "awg"})
        direct = next(item for item in engine["outbounds"] if item["tag"] == connector)
        self.assertEqual(direct, {"type": "block", "tag": connector})
        self.assertEqual(
            engine["dns"]["servers"][-1],
            {"type": "udp", "tag": "dns-" + connector, "server": "1.1.1.1", "detour": connector},
        )
        self.assertNotIn("secret-marker", json.dumps(engine))

    def test_two_ready_connectors_use_distinct_interfaces_and_dns(self):
        """Keep overlapping IPv4 profiles on distinct devices and reject slot aliasing."""
        self.profile["version"] = 2
        self.profile["connectors"] = []
        for idx, (group, tag) in enumerate(zip(self.profile["groups"][:2], ("awg-a", "awg-b"))):
            item = dict(id=tag, type="wireguard", group=group["id"], priority=len(group["exits"]) + 1,
                        status="ready", ipv6Blocked=True)
            if idx:
                item["slot"] = 1
            directory = self.base / "awg" / tag
            directory.mkdir(parents=True)
            meta = dict(item, ipv4Address="10.10.1.1/32", dnsIPv4="10.10.1.2")
            path = directory / "metadata.json"
            path.write_text(json.dumps(meta))
            path.chmod(0o600)
            self.profile["connectors"].append(item)
            group["exits"].append(tag)
            self.profile["healthy"][tag] = True
        _, backend = self.compile()
        for idx, tag in enumerate(("awg-a", "awg-b")):
            outbound = next(item for item in backend["outbounds"] if item["tag"] == tag)
            self.assertEqual((outbound["bind_interface"], outbound["routing_mark"]),
                             (f"awg{idx}", 514 + idx))
            self.assertEqual(outbound["domain_resolver"], "dns-" + tag)
            self.assertIn(dict(type="udp", tag="dns-" + tag, server="10.10.1.2", detour=tag),
                          backend["dns"]["servers"])
        for slot in (0, 50, True):
            with self.subTest(slot=slot):
                self.profile["connectors"][1]["slot"] = slot
                meta["slot"] = slot
                path.write_text(json.dumps(meta))
                with self.assertRaisesRegex(ValueError, "slot"):
                    self.compile()

    def test_upgrade_preserves_legacy_active_and_blocks_old_inactive_outbound(self):
        """Stage only the legacy inactive outbound change and retain the live legacy profile's slot zero."""
        self.profile = json.loads((Path(__file__).parent / "scheme3" / "guest-profile.json").read_text())
        group = self.profile["groups"][0]
        for tag, status in (("old-a", "ready"), ("old-b", "configured")):
            connector = dict(id=tag, type="wireguard", group=group["id"], priority=len(group["exits"]) + 1,
                             status=status, ipv6Blocked=True)
            self.profile["connectors"].append(connector)
            group["exits"].append(tag)
            self.profile["healthy"][tag] = status == "ready"
            directory = self.base / "awg" / tag
            directory.mkdir(parents=True)
            path = directory / "metadata.json"
            path.write_text(json.dumps(dict(connector, ipv4Address="10.1.2.4/32", dnsIPv4="10.1.2.1")))
            path.chmod(0o600)
        snapshot, backend = self.compile()
        active = next(item for item in backend["outbounds"] if item["tag"] == "old-a")
        active.pop("domain_resolver")
        direct = next(item for item in backend["outbounds"] if item["tag"] == "keenetic-direct")
        direct.pop("domain_resolver")
        local_server = backend["dns"]["servers"].pop()
        self.assertEqual(local_server, {"type": "local", "tag": "hestia-underlay-resolver"})
        inactive = next(item for item in backend["outbounds"] if item["tag"] == "old-b")
        inactive.update(type="direct", bind_interface="awg0", routing_mark=514)
        for name, content, digest in (("profile.json", self.profile, "profile-source.sha256"),
                                      ("sing-box.json", backend, "profile-backend.sha256"),
                                      ("snapshot.json", snapshot, None)):
            raw = json.dumps(content).encode()
            (self.base / name).write_bytes(raw)
            if digest:
                (self.base / digest).write_text(hashlib.sha256(raw).hexdigest())
        stage = self.base / "migration"
        stage.mkdir()
        cmd = [sys.executable, "-I", str(Path(__file__).parent / "profile.py")]
        subprocess.run([*cmd, "--stage-awg-backend", str(self.base), str(stage)], check=True)
        self.assertEqual(subprocess.check_output([*cmd, "--ready-awg", str(self.base)], text=True), "old-a\n")
        self.assertEqual(subprocess.check_output([*cmd, "--awg-start-plan", str(self.base)], text=True), "old-a 0 auto\n")
        raw = (stage / "sing-box.json").read_bytes()
        self.assertEqual((stage / "profile-backend.sha256").read_text().strip(), hashlib.sha256(raw).hexdigest())
        active["domain_resolver"] = "dns-old-a"
        direct["domain_resolver"] = "hestia-underlay-resolver"
        backend["dns"]["servers"].append(local_server)
        inactive.clear()
        inactive.update(type="block", tag="old-b")
        self.assertEqual(json.loads(raw), backend)

    def test_smoke_uses_live_health_per_connector(self):
        """A failed tunnel selects the next healthy exit, or deny when its group has no fallback."""
        config = {"healthy": {"awg-a": True, "awg-b": True}, "connectorKinds": {"awg-a": "awg", "awg-b": "awg"}}
        with patch("smoke.fresh_awg_heartbeat", side_effect=lambda tag: tag == "awg-b"):
            self.assertEqual(expected_target(config, {"exits": ["awg-a", "awg-b"]}), "awg-b")
            self.assertEqual(expected_target(config, {"exits": ["awg-a"]}), "deny")

    def test_ready_awg_connector_requires_healthy_snapshot(self):
        """Reject a ready connector unless its snapshot records the completed health check."""
        connector = "awg-test"
        directory = self.base / "awg" / connector
        directory.mkdir(parents=True, mode=0o700)
        metadata = {
            "id": connector,
            "group": "finland",
            "priority": 2,
            "status": "ready",
            "ipv6Blocked": False,
            "type": "wireguard",
            "ipv4Address": "10.66.66.2/32",
            "dnsIPv4": "1.1.1.1",
        }
        (directory / "metadata.json").write_text(json.dumps(metadata))
        (directory / "metadata.json").chmod(0o600)
        (directory / "profile.conf").write_text("synthetic profile")
        (directory / "profile.conf").chmod(0o600)
        self.profile["version"] = 2
        self.profile["connectors"] = [
            {
                "id": connector,
                "type": "wireguard",
                "group": "finland",
                "priority": 2,
                "ipv6Blocked": False,
                "status": "ready",
            }
        ]
        self.profile["groups"][1]["exits"].append(connector)
        with self.assertRaises(ValueError):
            self.compile()

    def test_scheme3_managed_profile_preserves_tun_direct_and_default_exit(self):
        """Compile the current scheme3 TUN/direct topology without changing any traffic path."""
        current = json.loads(
            (Path(__file__).parent / "scheme3" / "guest-sing-box.json").read_text()
        )
        profile = {
            "version": 2,
            "interfaces": [
                {"id": "keenetic-direct", "type": "direct", "bind_interface": "lima0"}
            ],
            "connectors": [],
            "groups": [
                {
                    "id": "default",
                    "exits": ["keenetic-direct"],
                    "defaultExit": "keenetic-direct",
                }
            ],
            "lists": [],
            "healthy": {"keenetic-direct": True},
            "inbounds": [json.loads(json.dumps(current["inbounds"][0]))],
        }
        snapshot, candidate = compile_profile(profile, self.base)
        self.assertTrue(semantically_equal_backend(candidate, current))
        self.assertEqual(
            snapshot,
            {"groups": [{"id": "default", "exits": ["keenetic-direct"]}], "lists": [], "healthy": {"keenetic-direct": True}},
        )
        self.assertEqual(candidate["inbounds"], current["inbounds"])
        self.assertEqual(candidate["outbounds"][0]["default"], "keenetic-direct")
        self.assertEqual(candidate["route"]["final"], "default")

    def test_batch_order_preserves_explicit_deny(self):
        """Moving another group ahead must not open a nonempty group whose bootstrap selector blocks traffic."""
        profile = json.loads((Path(__file__).parent / "scheme3" / "guest-profile.json").read_text())
        group = profile["groups"][0]
        group["defaultExit"] = "deny"
        profile["groups"].append({"id": "reserve", "exits": [], "defaultExit": "deny"})
        snapshot, backend = compile_profile(profile, self.base)
        for name, content, digest in (("profile.json", profile, "profile-source.sha256"),
                                      ("sing-box.json", backend, "profile-backend.sha256"),
                                      ("snapshot.json", snapshot, None)):
            data = json.dumps(content).encode()
            (self.base / name).write_bytes(data)
            if digest:
                (self.base / digest).write_text(hashlib.sha256(data).hexdigest())
        stage = self.base / "stage"
        stage.mkdir()
        stage_order(self.base, stage, list(reversed(snapshot["groups"])))
        _, _, candidate = managed_profile(stage)
        selector = next(out for out in candidate["outbounds"] if out["tag"] == group["id"])
        self.assertEqual(selector["default"], "deny")

    def test_scheme3_managed_profile_rejects_changed_bootstrap_path(self):
        """Reject an adoption candidate whose initial exit or TUN address differs from the live path."""
        current = json.loads(
            (Path(__file__).parent / "scheme3" / "guest-sing-box.json").read_text()
        )
        self.profile = {
            "version": 2,
            "interfaces": [
                {"id": "keenetic-direct", "type": "direct", "bind_interface": "lima0"}
            ],
            "connectors": [],
            "groups": [
                {"id": "default", "exits": ["keenetic-direct"], "defaultExit": "deny"}
            ],
            "lists": [],
            "healthy": {"keenetic-direct": True},
            "inbounds": [json.loads(json.dumps(current["inbounds"][0]))],
        }
        _, candidate = self.compile()
        self.assertFalse(semantically_equal_backend(candidate, current))
        self.profile["groups"][0]["defaultExit"] = "keenetic-direct"
        self.profile["inbounds"][0]["address"] = ["172.30.0.5/30"]
        _, changed = self.compile()
        self.assertFalse(semantically_equal_backend(changed, current))

    def test_managed_v2_verifies_full_scheme3_backend_semantics(self):
        """Validate a managed profile only when its backend preserves the exact TUN and direct-egress semantics."""
        backend = json.loads(
            (Path(__file__).parent / "scheme3" / "guest-sing-box.json").read_text()
        )
        self.profile = {
            "version": 2,
            "interfaces": [
                {"id": "keenetic-direct", "type": "direct", "bind_interface": "lima0"}
            ],
            "connectors": [],
            "groups": [
                {
                    "id": "default",
                    "exits": ["keenetic-direct"],
                    "defaultExit": "keenetic-direct",
                }
            ],
            "lists": [],
            "healthy": {"keenetic-direct": True},
            "inbounds": [json.loads(json.dumps(backend["inbounds"][0]))],
        }
        snapshot, _ = self.compile()
        for name, content in (("profile", self.profile), ("sing-box", backend), ("snapshot", snapshot)):
            raw = json.dumps(content).encode()
            (self.base / f"{name}.json").write_bytes(raw)
            if name != "snapshot":
                sidecar = "profile-source" if name == "profile" else "profile-backend"
                (self.base / f"{sidecar}.sha256").write_text(hashlib.sha256(raw).hexdigest())
        managed_profile(self.base)
        changed = dict(backend)
        changed["inbounds"] = [dict(backend["inbounds"][0], address=["172.30.0.9/30"])]
        raw = json.dumps(changed).encode()
        (self.base / "sing-box.json").write_bytes(raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            managed_profile(self.base)


class BindingTests(unittest.TestCase):
    """Check changes to managed profiles without requiring the VPN source assets."""

    def setUp(self):
        """Prepare a managed file set, then delete its unavailable source assets."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        for asset in EXAMPLES.iterdir():
            shutil.copyfile(asset, self.base / asset.name)
        self.profile = json.loads((self.base / "stand.json").read_text())
        snapshot, backend = compile_profile(self.profile, self.base)
        snapshot["healthy"] = {"fi-wg": True}
        self.backend = backend
        for name, data in (
            ("profile", self.profile),
            ("sing-box", backend),
            ("snapshot", snapshot),
        ):
            raw = json.dumps(data).encode()
            (self.base / (name + ".json")).write_bytes(raw)
            if name != "snapshot":
                sidecar = "profile-source" if name == "profile" else "profile-backend"
                (self.base / (sidecar + ".sha256")).write_text(
                    hashlib.sha256(raw).hexdigest()
                )
        for secret in self.base.glob("*.conf"):
            secret.unlink()
        self.stage = self.base / "stage"
        self.stage.mkdir(mode=0o700)

    def test_move_wireguard_without_reopening_source_config(self):
        """Move a legacy WG exit while preserving DNS, backend credentials and domain routing rules."""
        stage_move_exit(self.base, self.stage, "ru-wg", "russia", "finland", 2)
        profile, snapshot, backend = managed_profile(self.stage)
        expected = [{"id": "russia", "exits": []}, {"id": "finland", "exits": ["fi-wg", "ru-wg"]}]
        self.assertEqual(profile, dict(self.profile, groups=expected))
        self.assertEqual(snapshot["groups"], expected)
        self.assertEqual(snapshot["healthy"], {"fi-wg": True})
        self.assertEqual(backend["outbounds"][1]["outbounds"], ["deny"])
        self.assertEqual(backend["outbounds"][2]["outbounds"], ["fi-wg", "ru-wg", "deny"])
        self.assertEqual(backend, dict(self.backend, outbounds=backend["outbounds"]))

    def test_create_empty_group_without_reopening_wireguard_sources(self):
        """Create a deny-only selector while preserving the original routes, group order and runtime availability."""
        stage_create_group(self.base, self.stage, "new-group")
        profile, snapshot, backend = managed_profile(self.stage)
        group = {"id": "new-group", "exits": []}
        self.assertEqual(profile, dict(self.profile, groups=[*self.profile["groups"], group]))
        self.assertEqual(snapshot["healthy"], {"fi-wg": True})
        expected = [*self.backend["outbounds"], {
            "type": "selector", "tag": "new-group", "outbounds": ["deny"],
            "default": "deny", "interrupt_exist_connections": True,
        }]
        self.assertEqual(backend, dict(self.backend, outbounds=expected))

    def test_delete_group_preserves_bound_lists_as_unassigned(self):
        """Drop a named selector and its DNS routes while retaining masks and all unrelated backend state."""
        stage_create_group(self.base, self.stage, "remove-me", "Удаляемая")
        bound, deleted = self.base / "bound", self.base / "deleted"
        bound.mkdir()
        deleted.mkdir()
        stage_binding(self.stage, bound, "exception", "remove-me")
        stage_delete_group(bound, deleted, "remove-me")
        profile, snapshot, backend = managed_profile(deleted)
        expected = [dict(item, group="" if item["id"] == "exception" else item["group"]) for item in self.profile["lists"]]
        self.assertEqual(profile, dict(self.profile, lists=expected))
        self.assertEqual(snapshot["lists"], expected)
        self.assertEqual(snapshot["healthy"], {"fi-wg": True})
        self.assertEqual(backend["outbounds"], self.backend["outbounds"])
        self.assertFalse(any(item["outbound"] == "remove-me" for item in backend["route"].get("rules", [])))

    def test_display_name_survives_reorder_without_reopening_vpn_sources(self):
        """Rename a bound legacy group, reorder the groups, and verify selector tags, bindings and display name."""
        before = managed_profile(self.base)
        stage_rename_group(self.base, self.stage, "russia", "Домашняя сеть")
        renamed, snapshot, backend = managed_profile(self.stage)
        self.assertEqual(renamed["groups"][0], dict(self.profile["groups"][0], name="Домашняя сеть"))
        self.assertEqual(renamed["lists"], self.profile["lists"])
        self.assertEqual(backend, before[2])
        self.assertEqual(snapshot["groups"][0]["name"], "Домашняя сеть")
        ordered = self.base / "ordered"
        ordered.mkdir()
        stage_order(self.stage, ordered, list(reversed(self.profile["groups"])))
        ordered_profile, ordered_snapshot, _ = managed_profile(ordered)
        self.assertEqual(ordered_profile["groups"][-1]["name"], "Домашняя сеть")
        self.assertEqual(ordered_snapshot["groups"][-1]["id"], "russia")
        self.assertEqual(ordered_snapshot["groups"][-1]["name"], "Домашняя сеть")

    def test_binding_regenerates_derived_routes(self):
        """Rebinding an active list changes only routes, binding and metadata in staging."""
        stage_binding(self.base, self.stage, "exception", "finland")
        candidate = json.loads((self.stage / "sing-box.json").read_text())
        original = dict(self.backend)
        self.assertEqual(next(r["outbound"] for r in original.pop("route")["rules"] if "domain_suffix" in r), "russia")
        self.assertEqual(next(r["outbound"] for r in candidate.pop("route")["rules"] if "domain_suffix" in r), "finland")
        self.assertEqual(candidate, original)
        self.assertTrue(
            all(file.stat().st_mode & 0o077 == 0 for file in self.stage.iterdir())
        )
        self.assertEqual(
            json.loads((self.stage / "snapshot.json").read_text())["healthy"],
            {"fi-wg": True},
        )
        for filename, hashfile in (
            ("profile.json", "profile-source.sha256"),
            ("sing-box.json", "profile-backend.sha256"),
        ):
            self.assertEqual(
                (self.stage / hashfile).read_text().strip(),
                hashlib.sha256((self.stage / filename).read_bytes()).hexdigest(),
            )

    def test_order_stages_membership_transfer(self):
        """A complete saved order can move both exits into one group."""
        groups = [
            {"id": "russia", "exits": []},
            {"id": "finland", "exits": ["fi-wg", "ru-wg"]},
        ]
        stage_order(self.base, self.stage, groups)
        self.assertEqual(json.loads((self.stage / "snapshot.json").read_text())["groups"], groups)

    def test_committed_binding_exports_without_source_assets(self):
        """Export a rebound profile from staged files, then reproduce routing with restored VPN assets."""
        stage_binding(self.base, self.stage, "exception", "finland")
        spec = importlib.util.spec_from_file_location(
            "export_config", Path(__file__).with_name("export-config.py")
        )
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        output = self.base / "exported.json"
        exporter.export(output, self.stage)
        exported = json.loads(output.read_bytes())
        self.assertEqual(exported["healthy"], {"fi-wg": True})
        snapshot, backend = compile_profile(exported, EXAMPLES)
        self.assertEqual(
            snapshot, json.loads((self.stage / "snapshot.json").read_bytes())
        )
        self.assertEqual(
            backend, json.loads((self.stage / "sing-box.json").read_bytes())
        )
        (self.stage / ".binding-pending").mkdir()
        with self.assertRaises(ValueError):
            exporter.export(self.base / "uncommitted.json", self.stage)

    def test_detach_restores_broader_match(self):
        """Removing an exception falls back to a matching broader rule and retains the masks."""
        stage_binding(self.base, self.stage, "exception", "")
        routes = json.loads((self.stage / "sing-box.json").read_text())["route"][
            "rules"
        ]
        self.assertEqual(
            [(r["domain_suffix"], r["outbound"]) for r in routes if "domain_suffix" in r], [("com", "finland")]
        )
        changed = json.loads((self.stage / "profile.json").read_text())["lists"][1]
        self.assertEqual(
            changed, {"id": "exception", "group": "", "masks": ["*.deepseek.com"]}
        )

    def test_unknown_targets_cannot_be_staged(self):
        """Refuse absent list/group IDs while preserving the current live files."""
        for list_id, group in (("missing", "finland"), ("exception", "missing")):
            with (
                self.subTest(list_id=list_id, group=group),
                self.assertRaises(ValueError),
            ):
                stage_binding(self.base, self.stage, list_id, group)
            self.assertEqual(list(self.stage.iterdir()), [])

    def test_metadata_drift_rejected_without_staging(self):
        """Reject source, backend or topology drift before producing any candidate."""
        for filename in ("sing-box.json", "profile.json", "snapshot.json"):
            with self.subTest(filename=filename):
                path = self.base / filename
                original = path.read_bytes()
                modified = json.loads(original)
                if filename == "snapshot.json":
                    modified["lists"][1]["masks"] = []
                path.write_bytes(json.dumps(modified, indent=2).encode())
                with self.assertRaises(ValueError):
                    stage_binding(self.base, self.stage, "exception", "finland")
                self.assertEqual(list(self.stage.iterdir()), [])
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
