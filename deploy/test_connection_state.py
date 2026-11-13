"""Verify disabled native VPN runtimes using isolated synthetic profile assets."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from profile import compile_profile, pinned_paths, stage_generation, stage_order


class NativeConnectionStateTests(unittest.TestCase):
    """Keep disabled native VPN keys private while removing every live forwarding path."""

    def setUp(self):
        """Copy local fixtures and compile one enabled native VPN generation without network access."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        examples = Path(__file__).parent / "examples"
        for asset in examples.iterdir():
            shutil.copyfile(asset, self.base / asset.name)
        self.profile = json.loads((examples / "stand.json").read_text())
        self.profile["healthy"] = {"ru-wg": True, "fi-wg": True}
        self.snapshot, self.backend = compile_profile(self.profile, self.base)
        self.endpoint = next(item for item in self.backend["endpoints"] if item["tag"] == "ru-wg")
        self.server = next(item for item in self.backend["dns"]["servers"] if item["tag"] == "dns-ru-wg")
        self.profile["disabled_native_endpoints"] = {
            "ru-wg": {"endpoint": copy.deepcopy(self.endpoint), "server": copy.deepcopy(self.server)}
        }
        self.profile["disabled_connections"] = ["ru-wg"]

    def test_native_disable_removes_runtime_and_probe_path(self):
        """A disabled native VPN has a block public tag, no endpoint/probe, and unchanged group placement."""
        snapshot, backend = compile_profile(self.profile, self.base, self.backend)
        self.assertFalse(snapshot["healthy"]["ru-wg"])
        self.assertEqual(snapshot["groups"], self.snapshot["groups"])
        self.assertNotIn("ru-wg", [item["tag"] for item in backend.get("endpoints", [])])
        self.assertIn({"type": "block", "tag": "ru-wg"}, backend["outbounds"])
        self.assertNotIn("ru-wg", [item["id"] for item in pinned_paths(backend)])
        self.assertTrue(snapshot["healthy"]["fi-wg"])
        self.assertIn("fi-wg", [item["tag"] for item in backend["endpoints"]])

    def test_native_reenable_restores_committed_secrets_without_assets(self):
        """Re-enable recovers exact private endpoint material even after the original import file disappears."""
        _, disabled = compile_profile(self.profile, self.base, self.backend)
        (self.base / "ru-wg.conf").unlink()
        self.profile["disabled_connections"] = []
        snapshot, backend = compile_profile(self.profile, self.base, disabled)
        self.assertEqual(next(item for item in backend["endpoints"] if item["tag"] == "ru-wg"), self.endpoint)
        self.assertEqual(next(item for item in backend["dns"]["servers"] if item["tag"] == "dns-ru-wg"), self.server)
        self.assertTrue(snapshot["healthy"]["ru-wg"])
        self.assertNotIn("private_key", json.dumps(snapshot))

    def test_disabled_native_requires_archived_material(self):
        """Reject disabling a native VPN when its private recovery material was not retained."""
        self.profile.pop("disabled_native_endpoints")
        with self.assertRaisesRegex(ValueError, "archived configuration"):
            compile_profile(self.profile, self.base, self.backend)

    def test_group_reorder_preserves_disabled_native_block(self):
        """Reordering groups retains the native recovery archive and its blocking runtime route."""
        snapshot, backend = compile_profile(self.profile, self.base, self.backend)
        stage_generation(self.base, self.profile, snapshot, backend)
        stage = self.base / "ordered"
        stage.mkdir()
        stage_order(self.base, stage, list(reversed(self.profile["groups"])))
        saved_profile = json.loads((stage / "profile.json").read_text())
        saved_backend = json.loads((stage / "sing-box.json").read_text())
        saved_snapshot = json.loads((stage / "snapshot.json").read_text())
        self.assertEqual(saved_profile["disabled_connections"], ["ru-wg"])
        self.assertEqual(saved_profile["disabled_native_endpoints"], self.profile["disabled_native_endpoints"])
        self.assertIn({"type": "block", "tag": "ru-wg"}, saved_backend["outbounds"])
        self.assertNotIn("ru-wg", [item["tag"] for item in saved_backend.get("endpoints", [])])
        self.assertFalse(saved_snapshot["healthy"]["ru-wg"])
