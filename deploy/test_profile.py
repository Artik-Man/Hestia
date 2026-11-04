"""Run with python3 -m unittest discover -s deploy."""

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from profile import compile_profile, managed_profile, semantically_equal_backend, stage_binding, stage_order

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

    def test_domain_exceptions_and_unassigned_list(self):
        """Verify mask precedence, disabled lists, default group and isolated overlapping addresses."""
        snapshot, engine = self.compile()
        self.assertEqual(snapshot["lists"][-1]["group"], "")
        routes = engine["route"]
        self.assertEqual(routes["final"], "russia")
        self.assertEqual(
            [(r["domain_suffix"], r["outbound"]) for r in routes["rules"]],
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
            [(r["domain_suffix"], r["outbound"]) for r in candidate["route"]["rules"]],
            [("deepseek.com", "russia"), ("com", "finland"), ("com", "russia")],
        )
        self.assertEqual(
            candidate["outbounds"][1]["outbounds"], ["fi-backup", "fi-wg", "deny"]
        )
        self.assertEqual(
            json.loads((stage / "profile.json").read_bytes()),
            dict(self.profile, groups=groups),
        )

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
        connector = "awg-test"
        directory = self.base / "awg" / connector
        directory.mkdir(parents=True, mode=0o700)
        metadata = {
            "id": connector,
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
        self.assertEqual(direct["type"], "direct")
        self.assertEqual(direct["bind_interface"], "awg0")
        self.assertEqual(direct["routing_mark"], 514)
        self.assertEqual(
            engine["dns"]["servers"][-1],
            {"type": "udp", "tag": "dns-awg-test", "server": "1.1.1.1", "detour": connector},
        )
        self.assertNotIn("secret-marker", json.dumps(engine))

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

    def test_binding_regenerates_derived_routes(self):
        """Rebinding an active list changes only routes, binding and metadata in staging."""
        stage_binding(self.base, self.stage, "exception", "finland")
        candidate = json.loads((self.stage / "sing-box.json").read_text())
        original = dict(self.backend)
        self.assertEqual(original.pop("route")["rules"][0]["outbound"], "russia")
        self.assertEqual(candidate.pop("route")["rules"][0]["outbound"], "finland")
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

    def test_order_rejects_membership_transfer(self):
        """Transferring an exit to another group never produces private staging files."""
        groups = [
            {"id": "russia", "exits": []},
            {"id": "finland", "exits": ["fi-wg", "ru-wg"]},
        ]
        with self.assertRaises(ValueError):
            stage_order(self.base, self.stage, groups)
        self.assertEqual(list(self.stage.iterdir()), [])

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
            [(r["domain_suffix"], r["outbound"]) for r in routes], [("com", "finland")]
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
