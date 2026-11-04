"""Run with python3 -m unittest discover -s deploy."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from profile import compile_profile

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


if __name__ == "__main__":
    unittest.main()
