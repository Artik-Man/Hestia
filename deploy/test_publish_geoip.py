"""Check the ownership boundary between GeoIP proposals and live routing files."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from publish_geoip import publish


def rule(*hosts):
    """Encode an exact-IP proposal in the worker's format."""
    return json.dumps({"version": 3, "rules": [{"ip_cidr": list(hosts)}] if hosts else []})


class PublicationTests(unittest.TestCase):
    """Exercise validation, changed-only publication, and retention of the last valid batch."""

    def setUp(self):
        """Publish an initial two-country assignment in a private temporary directory."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / "proposals"
        self.target = Path(temporary.name) / "live"
        self.source.mkdir()
        self.target.mkdir()
        (self.source / "RU.json").write_text(rule("1.1.1.1/32"))
        (self.source / "DE.json").write_text(rule("2606:4700:4700::1111/128"))
        publish(self.source, self.target, "RU DE")
        self.original = self.contents()

    def contents(self):
        """Read live bytes and inode numbers to detect replacement of unchanged files."""
        return {p.name: (p.read_bytes(), p.stat().st_ino) for p in self.target.iterdir()}

    def test_changed_only(self):
        """Repeating the same batch preserves watched inodes and a removal clears only its country."""
        publish(self.source, self.target, "RU DE")
        self.assertEqual(self.contents(), self.original)
        (self.source / "RU.json").write_text(rule())
        publish(self.source, self.target, "RU DE")
        result = self.contents()
        self.assertEqual(result["DE.json"], self.original["DE.json"])
        self.assertEqual(json.loads(result["RU.json"][0])["rules"], [])

    def test_reject_whole_batch(self):
        """Reject arbitrary sing-box rules, private IPs, non-host prefixes, and duplicate assignments."""
        (self.source / "RU.json").write_text(rule("8.8.8.8/32"))
        for malformed in (
            '{"version":3,"rules":[{"domain_suffix":"ru"}]}',
            rule("10.0.0.1/32"),
            rule("64:ff9b::a00:1/128"),
            rule("4000::1/128"),
            rule("192.88.99.1/32"),
            rule("2001:20::1/128"),
            rule("8.8.4.0/24"),
            rule("8.8.8.8/32"),
        ):
            with self.subTest(malformed=malformed):
                (self.source / "DE.json").write_text(malformed)
                with self.assertRaises(ValueError):
                    publish(self.source, self.target, "RU DE")
                self.assertEqual(self.contents(), self.original)

    def test_reject_special_files(self):
        """Reject missing, linked, oversized, or FIFO proposals before publishing an earlier valid proposal."""
        (self.source / "RU.json").write_text(rule())
        path = self.source / "DE.json"
        path.unlink()
        for kind in ("missing", "link", "oversized", "fifo"):
            with self.subTest(kind=kind):
                if kind == "link":
                    path.symlink_to(self.source / "RU.json")
                if kind == "oversized":
                    path.write_bytes(b" " * (256 * 1024 + 1))
                if kind == "fifo":
                    os.mkfifo(path)
                with self.assertRaises((OSError, ValueError)):
                    publish(self.source, self.target, "RU DE")
                self.assertEqual(self.contents(), self.original)
                path.unlink(missing_ok=True)
