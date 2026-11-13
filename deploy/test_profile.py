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
    client_route,
    export_paths,
    geoip_directories,
    keenetic_default_route_device,
    KEENETIC_INGRESS_INBOUND,
    keenetic_interface_extension,
    managed_profile,
    normalize_legacy_ingress_route_order,
    pinned_paths,
    semantically_equal_backend,
    stage_binding,
    stage_create_group,
    stage_delete_group,
    stage_keenetic_ingress,
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

    def test_cpu_profiler_option_is_fixed_to_loopback_and_preserves_routing(self):
        """Compile the opt-in pprof listener without changing the snapshot or any other backend option."""
        profile = json.loads((Path(__file__).parent.parent / "scripts/deploy/default-profile-keenetic.json").read_text())
        snapshot_before, backend_before = compile_profile(profile, self.base)
        profile["diagnostics"] = {"cpuPprof": True}
        snapshot_enabled, backend_enabled = compile_profile(profile, self.base)
        self.assertEqual(snapshot_enabled, snapshot_before)
        expected = {"debug": {"listen": "127.0.0.1:6060"}}
        self.assertEqual(backend_enabled["experimental"]["debug"], expected["debug"])
        backend_enabled["experimental"].pop("debug")
        self.assertEqual(backend_enabled, backend_before)

        profile["diagnostics"] = {"cpuPprof": False}
        _, backend_disabled = compile_profile(profile, self.base)
        self.assertNotIn("debug", backend_disabled["experimental"])
        profile["diagnostics"] = {"cpuPprof": "0.0.0.0:6060"}
        with self.assertRaisesRegex(ValueError, "invalid CPU profiling setting"):
            compile_profile(profile, self.base)

    def install_managed_profile(self, base, profile):
        """Write one checksum-verified synthetic generation for managed profile transformation tests."""
        snapshot, backend = compile_profile(profile, base)
        profile_raw = json.dumps(profile).encode()
        backend_raw = json.dumps(backend).encode()
        (base / "profile.json").write_bytes(profile_raw)
        (base / "profile-source.sha256").write_text(hashlib.sha256(profile_raw).hexdigest())
        (base / "sing-box.json").write_bytes(backend_raw)
        (base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())
        (base / "snapshot.json").write_text(json.dumps(snapshot))
        return snapshot, backend

    def test_geoip_directories_follow_the_installed_platform_layout(self):
        """Resolve GeoIP rules and overrides inside Entware on Keenetic and standard paths elsewhere."""
        self.assertEqual(
            geoip_directories(Path("/opt/lib/hestia/profile.py")),
            (Path("/opt/share/hestia/geoip"), Path("/opt/var/lib/hestia-geoip-overrides")),
        )
        self.assertEqual(
            geoip_directories(Path("/usr/local/lib/hestia/profile.py")),
            (Path("/usr/share/hestia/geoip"), Path("/var/lib/hestia-geoip-overrides")),
        )

    def test_keenetic_ingress_enable_and_disable_are_reversible(self):
        """Add OpkgTun with an explicit AWG-only route, then remove it without losing SOCKS."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        awg_dir = self.base / "awg" / connector_id
        awg_dir.mkdir(parents=True)
        metadata = awg_dir / "metadata.json"
        metadata.write_text(json.dumps({
            "id": connector_id, "group": "amnezia", "priority": 1,
            "status": "ready", "ipv6Blocked": True, "type": "amneziawg",
            "ipv4Address": "10.8.1.5/32", "dnsIPv4": "1.1.1.1",
        }))
        metadata.chmod(0o600)
        self.profile["connectors"] = [{
            "id": connector_id, "type": "amneziawg", "group": "amnezia",
            "priority": 1, "ipv6Blocked": True, "status": "ready",
        }]
        self.profile["groups"].append({"id": "amnezia", "exits": [connector_id]})
        self.profile["lists"] = [{"id": "safe-domain", "group": "amnezia", "masks": ["*.safe.test"]}]
        self.profile["healthy"][connector_id] = True
        self.profile["version"] = 2
        self.profile.pop("socks_port")
        self.profile["inbounds"] = [{
            "type": "socks", "tag": "hestia-local-socks",
            "listen": "127.0.0.1", "listen_port": 1080,
        }]
        for group in self.profile["groups"]:
            group["defaultExit"] = "deny"
        self.install_managed_profile(self.base, self.profile)
        enabled_stage = self.base / "enabled"
        enabled_stage.mkdir()
        with patch("profile.keenetic_default_route_device", return_value="wan9"):
            stage_keenetic_ingress(self.base, enabled_stage, True)

        enabled_profile = json.loads((enabled_stage / "profile.json").read_bytes())
        enabled_snapshot = json.loads((enabled_stage / "snapshot.json").read_bytes())
        enabled_backend = json.loads((enabled_stage / "sing-box.json").read_bytes())
        self.assertEqual(enabled_profile["version"], 2)
        self.assertIn({
            "type": "socks", "tag": "hestia-local-socks", "listen": "127.0.0.1", "listen_port": 1080
        }, enabled_profile["inbounds"])
        self.assertEqual(enabled_profile["inbounds"][-1]["tag"], "hestia-keenetic-ingress")
        self.assertEqual(enabled_profile["inbounds"][-1]["stack"], "gvisor")
        self.assertEqual(enabled_snapshot["groups"], [
            {"id": group["id"], "exits": group["exits"]} for group in enabled_profile["groups"]
        ])
        self.assertTrue(
            {"hestia-local-socks", "hestia-keenetic-ingress"}.issubset(
                {item.get("tag") for item in enabled_backend["inbounds"]}
            )
        )
        self.assertIn(
            {"inbound": ["hestia-keenetic-ingress"], "action": "sniff", "timeout": "300ms"},
            enabled_backend["route"]["rules"],
        )
        ingress_rule = {
            "inbound": ["hestia-keenetic-ingress"],
            "action": "route",
            "outbound": "amnezia",
        }
        self.assertIn(ingress_rule, enabled_backend["route"]["rules"])
        self.assertGreater(
            enabled_backend["route"]["rules"].index(ingress_rule),
            enabled_backend["route"]["rules"].index(
                next(rule for rule in enabled_backend["route"]["rules"] if "domain_suffix" in rule)
            ),
        )

        disabled_stage = self.base / "disabled"
        disabled_stage.mkdir()
        shutil.copytree(self.base / "awg", enabled_stage / "awg")
        with patch("profile.keenetic_default_route_device", return_value="wan9"):
            stage_keenetic_ingress(enabled_stage, disabled_stage, False)
        disabled_profile = json.loads((disabled_stage / "profile.json").read_bytes())
        disabled_backend = json.loads((disabled_stage / "sing-box.json").read_bytes())
        self.assertNotIn("hestia-keenetic-ingress", [item["tag"] for item in disabled_profile["inbounds"]])
        self.assertIn("hestia-local-socks", [item["tag"] for item in disabled_backend["inbounds"]])

    def test_keenetic_ingress_accepts_safe_groups_and_uses_default_as_fallback(self):
        """Allow several safe policy targets and use the configured default group for unmatched ingress."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        hysteria_id = "2db91e0d-39d2-4194-a8b9-1c9fdc9c86bd"
        relay_id = "8f6f8820-52f0-4d87-956e-217b99a5d544"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [{"id": connector_id, "type": "amneziawg", "status": "ready"}],
            "hysteria2": [
                {"id": hysteria_id, "underlay": "keenetic-uplink"},
                {"id": relay_id, "underlay": "keenetic-opkgtun"},
            ],
            "groups": [{"id": "rest-of-world", "exits": [connector_id, hysteria_id], "defaultExit": "deny"}],
        }
        fallback = {"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "rest-of-world"}
        self.assertEqual(client_route(profile, "rest-of-world", [], [])[
            "rules"], [fallback])
        profile["groups"].append({"id": "also-safe", "exits": [connector_id], "defaultExit": "deny"})
        self.assertEqual(client_route(profile, "rest-of-world", [], [])[
            "rules"], [fallback])
        profile["groups"].pop()
        profile["groups"][0]["exits"].append("direct-wan")
        self.assertEqual(
            client_route(profile, "rest-of-world", [], [])["rules"],
            [{"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "deny"}],
        )
        profile["groups"][0]["exits"] = [connector_id, hysteria_id]
        profile["hysteria2"][0]["underlay"] = relay_id
        self.assertEqual(
            client_route(profile, "rest-of-world", [], [])["rules"],
            [{"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "deny"}],
        )
        profile["hysteria2"][0]["underlay"] = "keenetic-uplink"
        profile["groups"][0]["defaultExit"] = connector_id
        self.assertEqual(client_route(profile, "rest-of-world", [], [])[
            "rules"], [fallback])
        profile["groups"][0]["defaultExit"] = "direct-wan"
        self.assertEqual(
            client_route(profile, "rest-of-world", [], [])["rules"],
            [{"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "deny"}],
        )

    def test_keenetic_ingress_allows_provider_exit_bound_to_current_uplink(self):
        """Allow the explicit provider interface beside VPN exits when it matches the active WAN device."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [{"id": connector_id, "type": "amneziawg", "status": "ready"}],
            "hysteria2": [],
            "interfaces": [{"id": "keenetic-uplink", "type": "direct", "bind_interface": "eth3"}],
            "groups": [{
                "id": "russia",
                "exits": [connector_id, "keenetic-uplink"],
                "defaultExit": "keenetic-uplink",
            }],
        }

        with patch("profile.keenetic_default_route_device", return_value="eth3"):
            route = client_route(profile, "russia", [], [])

        self.assertEqual(
            route["rules"],
            [{"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "russia"}],
        )
        domain_rule = {"domain_suffix": "ru", "action": "route", "outbound": "russia"}
        with patch("profile.keenetic_default_route_device", return_value="eth3"):
            routed = client_route(profile, "russia", [domain_rule], [])
        self.assertIn(domain_rule, routed["rules"])

    def test_keenetic_ingress_rejects_provider_exit_not_bound_to_current_uplink(self):
        """Fail closed when the configured provider interface differs from the verified default WAN."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [{"id": connector_id, "type": "amneziawg", "status": "ready"}],
            "hysteria2": [],
            "interfaces": [{"id": "keenetic-uplink", "type": "direct", "bind_interface": "eth2"}],
            "groups": [{
                "id": "russia",
                "exits": [connector_id, "keenetic-uplink"],
                "defaultExit": connector_id,
            }],
        }

        with patch("profile.keenetic_default_route_device", return_value="eth3"):
            route = client_route(profile, "russia", [], [])

        self.assertEqual(
            route["rules"],
            [{"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "deny"}],
        )

    def test_managed_profile_normalizes_only_legacy_ingress_rule_order(self):
        """Migrate the exact previous ingress-before-domain ordering while preserving other route changes."""
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [],
            "groups": [],
        }
        domain_rule = {"domain_suffix": "ru", "action": "route", "outbound": "russia"}
        fallback = {"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "world"}
        pinned = [{"ip_cidr": ["192.0.2.1/32"], "action": "route", "outbound": "deny"}]
        expected_rules = [*pinned, {"inbound": ["hestia-keenetic-ingress"], "action": "sniff", "timeout": "300ms"}, domain_rule, fallback]
        expected = {"final": "world", "rules": expected_rules}
        actual = {
            "final": "world",
            "rules": [*pinned, expected_rules[1], fallback, domain_rule],
        }

        normalize_legacy_ingress_route_order(actual, expected, profile, pinned, [domain_rule])

        self.assertEqual(actual, expected)
        altered = {"final": "world", "rules": [*pinned, expected_rules[1], fallback, domain_rule, {"action": "deny"}]}
        normalize_legacy_ingress_route_order(altered, expected, profile, pinned, [domain_rule])
        self.assertNotEqual(altered, expected)

    def test_keenetic_ingress_applies_domain_then_country_then_safe_fallback(self):
        """Route ingress by domains before GeoIP and reserve the safe default group for unmatched traffic."""
        root = Path(__file__).resolve().parents[1]
        codes = (root / "backend/internal/geoip/countries.txt").read_text().split()
        geoip_dir = self.base / "geoip"
        overrides_dir = self.base / "overrides"
        geoip_dir.mkdir()
        overrides_dir.mkdir()
        (geoip_dir / "manifest.json").write_text(json.dumps({"countries": ["RU", "US"]}))
        awg_world = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        awg_russia = "2db91e0d-39d2-4194-a8b9-1c9fdc9c86bd"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [
                {"id": awg_world, "type": "amneziawg", "status": "ready"},
                {"id": awg_russia, "type": "amneziawg", "status": "ready"},
            ],
            "hysteria2": [],
            "groups": [
                {"id": "rest-of-world", "exits": [awg_world], "defaultExit": awg_world},
                {"id": "russia", "exits": [awg_russia], "defaultExit": awg_russia},
            ],
            "countryMap": {
                "enabled": True,
                "version": "test-version",
                "assignments": {code: "rest-of-world" for code in codes},
            },
        }
        profile["countryMap"]["assignments"]["RU"] = "russia"
        domain_rule = {"domain_suffix": "ru", "action": "route", "outbound": "rest-of-world"}

        with patch("profile.GEOIP_DIRECTORY", geoip_dir), patch("profile.GEOIP_OVERRIDES", overrides_dir):
            route = client_route(profile, "rest-of-world", [domain_rule], [])

        rules = route["rules"]
        fallback = {"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "rest-of-world"}
        domain_index = rules.index(domain_rule)
        country_index = next(
            index for index, rule in enumerate(rules)
            if rule.get("rule_set") == ["geoip-RU"]
        )
        fallback_index = rules.index(fallback)
        self.assertLess(domain_index, country_index)
        self.assertLess(country_index, fallback_index)
        self.assertIn(
            {"type": "local", "tag": "geoip-RU", "format": "source", "path": str(geoip_dir / "RU.json")},
            route["rule_set"],
        )

    def test_keenetic_ingress_rejects_unsafe_country_route_group(self):
        """Reject an ingress GeoIP target whose VPN underlay would re-enter through OpkgTun."""
        root = Path(__file__).resolve().parents[1]
        codes = (root / "backend/internal/geoip/countries.txt").read_text().split()
        geoip_dir = self.base / "geoip"
        overrides_dir = self.base / "overrides"
        geoip_dir.mkdir()
        overrides_dir.mkdir()
        (geoip_dir / "manifest.json").write_text(json.dumps({"countries": ["RU"]}))
        awg_world = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        relay_id = "2db91e0d-39d2-4194-a8b9-1c9fdc9c86bd"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [{"id": awg_world, "type": "amneziawg", "status": "ready"}],
            "hysteria2": [{"id": relay_id, "underlay": "keenetic-opkgtun"}],
            "groups": [
                {"id": "rest-of-world", "exits": [awg_world], "defaultExit": awg_world},
                {"id": "russia", "exits": [relay_id], "defaultExit": relay_id},
            ],
            "countryMap": {
                "enabled": True,
                "version": "test-version",
                "assignments": {code: "rest-of-world" for code in codes},
            },
        }
        profile["countryMap"]["assignments"]["RU"] = "russia"

        with patch("profile.GEOIP_DIRECTORY", geoip_dir), patch("profile.GEOIP_OVERRIDES", overrides_dir):
            with self.assertRaisesRegex(ValueError, "unsafe Keenetic ingress route group: russia"):
                client_route(profile, "rest-of-world", [], [])

    def test_keenetic_ingress_rejects_unsafe_domain_route_group(self):
        """Reject a domain binding to a group whose Hysteria transport recursively uses OpkgTun."""
        awg_world = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        relay_id = "2db91e0d-39d2-4194-a8b9-1c9fdc9c86bd"
        profile = {
            "inbounds": [{"type": "tun", "tag": "hestia-keenetic-ingress"}],
            "connectors": [{"id": awg_world, "type": "amneziawg", "status": "ready"}],
            "hysteria2": [{"id": relay_id, "underlay": "keenetic-opkgtun"}],
            "groups": [
                {"id": "rest-of-world", "exits": [awg_world], "defaultExit": awg_world},
                {"id": "russia", "exits": [relay_id], "defaultExit": relay_id},
            ],
        }
        domain_rule = {"domain_suffix": "ru", "action": "route", "outbound": "russia"}

        with self.assertRaisesRegex(ValueError, "unsafe Keenetic ingress route group: russia"):
            client_route(profile, "rest-of-world", [domain_rule], [])

    def test_keenetic_interface_extension_is_narrowly_scoped(self):
        """Permit only the reserved Keenetic underlay bound to the discovered uplink device."""
        base = [{"id": "existing", "type": "direct", "bind_interface": "eth2"}]
        expected = base + [{"id": "keenetic-uplink", "type": "direct", "bind_interface": "wan9"}]
        self.assertTrue(keenetic_interface_extension(base, expected, "wan9"))
        self.assertTrue(keenetic_interface_extension(expected, expected, "wan9"))
        self.assertFalse(keenetic_interface_extension(base, expected[:-1] + [dict(expected[-1], bind_interface="eth2")], "wan9"))
        self.assertFalse(keenetic_interface_extension(base, base + [dict(expected[-1]), dict(expected[-1], id="other")], "wan9"))

    def test_keenetic_default_route_device_selects_unique_best_metric(self):
        """Resolve the provider transport from the uniquely preferred default-route device."""
        output = "default via 10.0.0.1 dev wan9 metric 1000\n"
        with patch("profile.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            self.assertEqual(keenetic_default_route_device(), "wan9")
        output = "default via 10.0.0.1 dev eth2 metric 200\ndefault via 10.0.0.2 dev wan9 metric 100\n"
        with patch("profile.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            self.assertEqual(keenetic_default_route_device(), "wan9")
        output = "default via 10.0.0.1 dev eth2 metric 100\ndefault via 10.0.0.2 dev wan9 metric 100\n"
        with patch("profile.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaisesRegex(ValueError, "one Keenetic default route"):
                keenetic_default_route_device()

    def test_group_order_adds_keenetic_uplink_without_changing_default_exit(self):
        """Add the discovered provider to a group while retaining its existing default and VPN inputs."""
        self.profile["version"] = 2
        self.profile.pop("socks_port")
        self.profile["connectors"] = []
        self.profile["inbounds"] = [
            {"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": 1080}
        ]
        for group in self.profile["groups"]:
            group["defaultExit"] = "deny"
        snapshot, backend = self.compile()
        profile_raw = json.dumps(self.profile).encode()
        backend_raw = json.dumps(backend).encode()
        snapshot_raw = json.dumps(snapshot).encode()
        (self.base / "profile.json").write_bytes(profile_raw)
        (self.base / "profile-source.sha256").write_text(hashlib.sha256(profile_raw).hexdigest())
        (self.base / "sing-box.json").write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())
        (self.base / "snapshot.json").write_bytes(snapshot_raw)
        stage = self.base / "stage"
        stage.mkdir()
        groups = [
            {"id": group["id"], "exits": [*group["exits"]]}
            for group in self.profile["groups"]
        ]
        groups[0]["exits"].append("keenetic-uplink")

        with patch("profile.keenetic_default_route_device", return_value="wan9"):
            stage_order(self.base, stage, groups, "wan9", keenetic=True)

        staged_profile = json.loads((stage / "profile.json").read_bytes())
        staged_snapshot = json.loads((stage / "snapshot.json").read_bytes())
        staged_backend = json.loads((stage / "sing-box.json").read_bytes())
        self.assertEqual(staged_profile["interfaces"][-1], {
            "id": "keenetic-uplink", "type": "direct", "bind_interface": "wan9"
        })
        self.assertEqual(staged_profile["groups"][0]["exits"], ["ru-wg", "keenetic-uplink"])
        self.assertEqual(staged_snapshot["groups"][0]["exits"], ["ru-wg", "keenetic-uplink"])
        self.assertEqual(
            next(item for item in staged_backend["outbounds"] if item.get("tag") == "russia")["default"],
            next(item for item in backend["outbounds"] if item.get("tag") == "russia")["default"],
        )
        self.assertEqual(
            next(item for item in staged_backend["outbounds"] if item.get("tag") == "keenetic-uplink")["bind_interface"],
            "wan9",
        )

    def test_country_route_and_domain_precedence(self):
        """Recompile the same client policy after a group reorder without changing fixed listener routes."""
        codes = (
            (
                Path(__file__).resolve().parents[1]
                / "backend/internal/geoip/countries.txt"
            )
            .read_text()
            .split()
        )
        assignments = dict.fromkeys(codes, "russia")
        assignments["FI"] = "finland"
        self.profile["countryMap"] = {
            "enabled": True,
            "version": "fixture",
            "assignments": assignments,
        }
        (self.base / "manifest.json").write_text(
            json.dumps({"countries": ["FI", "RU"]})
        )
        with patch("profile.GEOIP_DIRECTORY", self.base):
            snapshot, backend = self.compile()
            self.assertEqual(snapshot["countryMap"], self.profile["countryMap"])
            route = backend["route"]
            exact, base = [
                rule
                for rule in route["rules"]
                if rule.get("outbound") == "finland" and "rule_set" in rule
            ]
            self.assertEqual(exact["rule_set"], ["exact-FI"])
            self.assertEqual(base["rule_set"], ["geoip-FI"])
            self.assertLess(route["rules"].index(exact), route["rules"].index(base))
            masks = [
                i for i, rule in enumerate(route["rules"]) if "domain_suffix" in rule
            ]
            self.assertLess(max(masks), route["rules"].index(exact))
            self.assertEqual(route["final"], "russia")
            self.assertNotIn("geoip-RU", [rule["tag"] for rule in route["rule_set"]])
            self.profile["groups"].reverse()
            _, backend = self.compile()
            self.assertEqual(backend["route"]["final"], "finland")
            self.assertEqual(
                backend["route"]["rules"][-1],
                {"action": "route", "outbound": "russia", "rule_set": ["geoip-RU"]},
            )
            self.profile["countryMap"]["enabled"] = False
            _, backend = self.compile()
            self.assertNotIn("rule_set", backend["route"])

    def test_keenetic_country_route_uses_compiled_geoip_rule_sets(self):
        """Use compact binary GeoIP sets on Keenetic while exact IP overrides remain reloadable JSON."""
        codes = (
            (Path(__file__).resolve().parents[1] / "backend/internal/geoip/countries.txt")
            .read_text()
            .split()
        )
        assignments = dict.fromkeys(codes, "russia")
        assignments["FI"] = "finland"
        self.profile["countryMap"] = {
            "enabled": True,
            "version": "fixture",
            "assignments": assignments,
        }
        (self.base / "manifest.json").write_text(json.dumps({"countries": ["FI", "RU"]}))
        (self.base / "FI.srs").write_bytes(b"compiled")
        with (
            patch("profile.GEOIP_BINARY", True),
            patch("profile.GEOIP_DIRECTORY", self.base),
            patch("profile.GEOIP_OVERRIDES", self.base),
        ):
            _, backend = self.compile()
        geoip = next(item for item in backend["route"]["rule_set"] if item["tag"] == "geoip-FI")
        exact = next(item for item in backend["route"]["rule_set"] if item["tag"] == "exact-FI")
        self.assertEqual((geoip["format"], geoip["path"]), ("binary", str(self.base / "FI.srs")))
        self.assertEqual((exact["format"], exact["path"]), ("source", str(self.base / "FI.json")))

    def test_ordered_hysteria_candidates_and_cycle(self):
        """Compile independent physical and VPN clients, probe each privately and reject cross-protocol cycles."""
        self.profile.update(version=2, connectors=[])
        self.profile["interfaces"].append({"id": "wan", "type": "direct", "bind_interface": "eth0"})
        self.profile["groups"][0]["exits"].extend(["wan", "relay", "parent"])
        base = {"name": "Test", "server": "test.example", "port": 443, "password": "test-only",
                "probeSecret": "b0" * 32}
        relay = dict(base, id="relay", underlays=["wan", "fi-wg", "parent"])
        parent = dict(base, id="parent")
        self.profile["hysteria2"] = [relay, parent]
        _, compiled = self.compile()
        out = {item["tag"]: item for item in compiled["outbounds"]}
        self.assertEqual(out["relay"]["outbounds"], ["_hy2/relay/wan", "_hy2/relay/fi-wg", "_hy2/relay/parent", "deny"])
        self.assertEqual(out["relay"]["default"], "deny")
        self.assertEqual(out["_hy2/relay/wan"]["bind_interface"], "eth0")
        self.assertEqual(out["_hy2/relay/fi-wg"]["detour"], "fi-wg")
        self.assertEqual(out["_hy2/relay/parent"]["detour"], "parent")
        self.assertNotIn("bind_interface", out["parent"])
        paths = [item for item in pinned_paths(compiled) if item.get("relay") == "relay"]
        self.assertEqual([item["candidate"] for item in paths], relay["underlays"])
        self.assertEqual(len(set(item["socksPassword"] for item in paths)), 3)
        parent["underlays"] = ["relay"]
        with self.assertRaisesRegex(ValueError, "cyclic"):
            self.compile()

    def test_disabled_hysteria_blocks_public_private_and_probe_paths(self):
        """An administratively disabled relay has no usable public or private QUIC path after restart."""
        self.profile.update(version=2, connectors=[])
        self.profile["interfaces"].append({"id": "wan", "type": "direct", "bind_interface": "eth0"})
        self.profile["groups"][0]["exits"].extend(["wan", "relay", "parent"])
        base = {"name": "Test", "server": "test.example", "port": 443, "password": "test-only", "probeSecret": "b0" * 32}
        self.profile["hysteria2"] = [dict(base, id="relay", underlays=["wan", "parent"]), dict(base, id="parent")]
        self.profile["healthy"].update(relay=True, parent=True)
        enabled_snapshot, enabled_backend = self.compile()
        self.profile["disabled_connections"] = ["relay"]
        snapshot, compiled = self.compile()
        out = {item["tag"]: item for item in compiled["outbounds"]}
        for tag in ("relay", "_hy2/relay/wan", "_hy2/relay/parent"):
            self.assertEqual(out[tag], {"type": "block", "tag": tag})
        self.assertFalse(snapshot["healthy"]["relay"])
        self.assertTrue(snapshot["healthy"]["parent"])
        self.assertFalse(any(path["id"] == "relay" or path.get("relay") == "relay" for path in pinned_paths(compiled)))
        self.install_managed_profile(self.base, self.profile)
        managed_profile(self.base)
        stage = self.base / "reordered-disabled-hysteria"
        stage.mkdir(mode=0o700)
        order = [{"id": group["id"], "exits": list(group["exits"])} for group in reversed(self.profile["groups"])]
        stage_order(self.base, stage, order)
        _, staged_snapshot, staged_backend = managed_profile(stage)
        self.assertFalse(staged_snapshot["healthy"]["relay"])
        self.assertEqual(next(item for item in staged_backend["outbounds"] if item["tag"] == "relay"), {"type": "block", "tag": "relay"})
        self.profile["disabled_connections"] = []
        self.assertEqual(self.compile(), (enabled_snapshot, enabled_backend))

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

        provider = {"id": "keenetic-uplink", "type": "direct", "bind_interface": "wan9"}
        self.profile["interfaces"].append(provider)
        self.profile["groups"][1]["exits"].append(provider["id"])
        self.profile["connectors"][0].update(status="ready", slot=0, underlays=[provider["id"]])
        self.profile["healthy"].update({provider["id"]: True, connector: True})
        metadata.update(status="ready", underlays=[provider["id"]], slot=0)
        (directory / "metadata.json").write_text(json.dumps(metadata))
        (directory / "profile.conf").write_text(
            "[Interface]\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\nPrivateKey = secret-marker\n"
            "[Peer]\nPublicKey = cHVi\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
        _, routed = self.compile()
        direct = next(item for item in routed["outbounds"] if item["tag"] == provider["id"])
        self.assertEqual(direct["bind_interface"], "wan9")
        transport = next(rule for rule in routed["route"]["rules"] if rule.get("inbound") == ["_wg-transport-0-0"])
        self.assertEqual(transport["outbound"], provider["id"])

        self.profile["disabled_connections"] = [connector]
        snapshot, disabled = self.compile()
        self.assertFalse(snapshot["healthy"][connector])
        self.assertTrue(self.profile["healthy"][connector])
        self.assertEqual(next(item for item in disabled["outbounds"] if item["tag"] == connector), {"type": "block", "tag": connector})
        self.assertFalse(any(item["id"] == connector for item in pinned_paths(disabled)))
        self.assertFalse(any(item.get("tag", "").startswith("_wg-transport-") for item in disabled["inbounds"]))
        self.install_managed_profile(self.base, self.profile)
        managed_profile(self.base)
        stage = self.base / "reordered-disabled-awg"
        stage.mkdir(mode=0o700)
        shutil.copytree(self.base / "awg", stage / "awg")
        order = [{"id": group["id"], "exits": list(group["exits"])} for group in reversed(self.profile["groups"])]
        stage_order(self.base, stage, order)
        _, staged_snapshot, staged_backend = managed_profile(stage)
        self.assertFalse(staged_snapshot["healthy"][connector])
        self.assertEqual(next(item for item in staged_backend["outbounds"] if item["tag"] == connector), {"type": "block", "tag": connector})

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

    def test_reorder_repairs_stale_ingress_route_to_empty_group(self):
        """Recover a route-equivalent empty-group ingress target and publish the requested order."""
        profile = json.loads((Path(__file__).parent / "scheme3" / "guest-profile.json").read_text())
        profile["connectors"] = []
        profile["inbounds"] = [dict(KEENETIC_INGRESS_INBOUND)]
        profile["groups"].append({"id": "reserve", "exits": [], "defaultExit": "deny"})
        snapshot, backend = self.install_managed_profile(self.base, profile)
        ingress_rule = {
            "inbound": ["hestia-keenetic-ingress"],
            "action": "route",
            "outbound": "deny",
        }
        self.assertIn(ingress_rule, backend["route"]["rules"])
        ingress_index = next(
            index
            for index, rule in enumerate(backend["route"]["rules"])
            if rule.get("inbound") == ["hestia-keenetic-ingress"] and rule.get("action") == "route"
        )
        backend["route"]["rules"][ingress_index]["outbound"] = "reserve"
        backend_path = self.base / "sing-box.json"
        backend_raw = json.dumps(backend).encode()
        backend_path.write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())

        stage = self.base / "stage"
        stage.mkdir()
        groups = list(reversed(snapshot["groups"]))
        stage_order(self.base, stage, groups)
        _, staged_snapshot, staged_backend = managed_profile(stage)
        self.assertEqual(staged_snapshot["groups"], groups)
        self.assertIn(ingress_rule, staged_backend["route"]["rules"])

        backend["route"]["rules"][ingress_index]["outbound"] = "default"
        backend_raw = json.dumps(backend).encode()
        backend_path.write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())
        with self.assertRaisesRegex(ValueError, "backend routes differ from the installed profile"):
            managed_profile(self.base)

    def test_reorder_repairs_stale_deny_ingress_route_to_safe_group(self):
        """Recompile one exact stale deny ingress route to the eligible AWG group during reorder."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        awg_dir = self.base / "awg" / connector_id
        awg_dir.mkdir(parents=True)
        (awg_dir / "metadata.json").write_text(json.dumps({
            "id": connector_id,
            "group": "vpn",
            "priority": 1,
            "status": "ready",
            "ipv6Blocked": True,
            "type": "amneziawg",
            "ipv4Address": "10.8.1.5/32",
            "dnsIPv4": "1.1.1.1",
        }))
        (awg_dir / "metadata.json").chmod(0o600)
        profile = json.loads((Path(__file__).parent / "scheme3" / "guest-profile.json").read_text())
        profile["connectors"] = [{
            "id": connector_id,
            "type": "amneziawg",
            "group": "vpn",
            "priority": 1,
            "ipv6Blocked": True,
            "status": "ready",
        }]
        profile["interfaces"] = []
        profile["groups"] = [
            {"id": "vpn", "exits": [connector_id], "defaultExit": "deny"},
            {"id": "reserve", "exits": [], "defaultExit": "deny"},
        ]
        profile["healthy"] = {connector_id: True}
        profile["inbounds"] = [dict(KEENETIC_INGRESS_INBOUND)]
        snapshot, backend = self.install_managed_profile(self.base, profile)
        ingress_index = next(
            index
            for index, rule in enumerate(backend["route"]["rules"])
            if rule.get("inbound") == ["hestia-keenetic-ingress"] and rule.get("action") == "route"
        )
        self.assertEqual(backend["route"]["rules"][ingress_index]["outbound"], "vpn")

        backend["route"]["rules"][ingress_index]["outbound"] = "deny"
        backend_path = self.base / "sing-box.json"
        backend_raw = json.dumps(backend).encode()
        backend_path.write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())

        stage = self.base / "stage"
        stage.mkdir()
        shutil.copytree(self.base / "awg", stage / "awg")
        stage_order(self.base, stage, list(reversed(snapshot["groups"])))
        _, staged_snapshot, staged_backend = managed_profile(stage)
        self.assertEqual(staged_snapshot["groups"][0]["id"], "reserve")
        self.assertEqual(
            staged_backend["route"]["rules"][ingress_index]["outbound"],
            "vpn",
        )

        backend["route"]["rules"][ingress_index]["outbound"] = "deny"
        backend["route"]["rules"][ingress_index]["unexpected"] = True
        backend_raw = json.dumps(backend).encode()
        backend_path.write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())
        with self.assertRaisesRegex(ValueError, "backend routes differ from the installed profile"):
            managed_profile(self.base)

        backend["route"]["rules"][ingress_index]["outbound"] = "reserve"
        backend["route"]["rules"][ingress_index]["extra"] = "unexpected"
        backend_raw = json.dumps(backend).encode()
        backend_path.write_bytes(backend_raw)
        (self.base / "profile-backend.sha256").write_text(hashlib.sha256(backend_raw).hexdigest())
        with self.assertRaisesRegex(ValueError, "backend routes differ from the installed profile"):
            managed_profile(self.base)

    def test_move_exit_updates_keenetic_ingress_target(self):
        """Moving the last safe VPN exit also moves the client ingress route to its new group."""
        connector_id = "7f02067a-ca17-4c38-ae26-7c7fb21ca06a"
        awg_dir = self.base / "awg" / connector_id
        awg_dir.mkdir(parents=True)
        metadata = {
            "id": connector_id,
            "group": "vpn",
            "priority": 1,
            "status": "ready",
            "ipv6Blocked": True,
            "type": "amneziawg",
            "ipv4Address": "10.8.1.5/32",
            "dnsIPv4": "1.1.1.1",
        }
        (awg_dir / "metadata.json").write_text(json.dumps(metadata))
        (awg_dir / "metadata.json").chmod(0o600)
        profile = json.loads((Path(__file__).parent / "scheme3" / "guest-profile.json").read_text())
        profile["connectors"] = [
            {
                "id": connector_id,
                "type": "amneziawg",
                "group": "vpn",
                "priority": 1,
                "ipv6Blocked": True,
                "status": "ready",
            }
        ]
        profile["interfaces"] = []
        profile["groups"] = [
            {"id": "vpn", "exits": [connector_id], "defaultExit": "deny"},
            {"id": "reserve", "exits": [], "defaultExit": "deny"},
        ]
        profile["healthy"] = {connector_id: True}
        profile["inbounds"] = [dict(KEENETIC_INGRESS_INBOUND)]
        self.install_managed_profile(self.base, profile)
        stage = self.base / "stage"
        stage.mkdir()
        shutil.copytree(self.base / "awg", stage / "awg")

        stage_move_exit(self.base, stage, connector_id, "vpn", "reserve", 1)
        _, moved_snapshot, moved_backend = managed_profile(stage)
        self.assertEqual(moved_snapshot["groups"][1]["exits"], [connector_id])
        self.assertIn(
            {"inbound": ["hestia-keenetic-ingress"], "action": "route", "outbound": "reserve"},
            moved_backend["route"]["rules"],
        )

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

    def test_hysteria_compilation_preserves_committed_native_wireguard(self):
        """Add an authenticated exit alongside native WG endpoints after installer secrets have been removed."""
        direct = {"type": "direct", "id": "wan", "bind_interface": "eth0"}
        self.profile["interfaces"].append(direct)
        self.profile["groups"][0]["exits"].append("wan")
        backend = self.backend
        backend["outbounds"].append({"type": "direct", "tag": "wan", "bind_interface": "eth0"})
        # The fixture represents a pre-existing installed physical exit.
        snapshot = json.loads((self.base / "snapshot.json").read_text())
        snapshot["groups"] = self.profile["groups"]
        (self.base / "snapshot.json").write_text(json.dumps(snapshot))
        for name, sidecar, obj in (("profile", "profile-source", self.profile), ("sing-box", "profile-backend", backend)):
            data = json.dumps(obj).encode()
            (self.base / (name + ".json")).write_bytes(data)
            (self.base / (sidecar + ".sha256")).write_text(hashlib.sha256(data).hexdigest())
        candidate = dict(self.profile, version=2, connectors=[], hysteria2=[
            {"id": "relay", "name": "Test", "underlay": "wan", "server": "example.test", "port": 443, "password": "test-only", "probeSecret": "a5" * 32}
        ])
        candidate["groups"][1]["exits"].append("relay")
        path = self.stage / "profile.json"
        path.write_text(json.dumps(candidate))
        subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("profile.py")),
                        str(path), str(self.stage), str(self.stage), str(self.base)], check=True)
        compiled = json.loads((self.stage / "sing-box.json").read_text())
        self.assertEqual(compiled["endpoints"], backend["endpoints"])
        relay = next(item for item in compiled["outbounds"] if item["tag"] == "relay")
        self.assertEqual(relay["bind_interface"], "eth0")
        self.assertEqual(relay["tls"], {"enabled": True, "server_name": "example.test"})
        self.assertIn({"type": "udp", "tag": "dns-relay", "server": "1.1.1.1", "detour": "relay"}, compiled["dns"]["servers"])

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
