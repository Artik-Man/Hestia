"""Exercise the GeoIP importer's shared IPv4/IPv6 routing and journal contract."""

import gzip
import json
import struct
import tempfile
import unittest
from pathlib import Path

import import_geoip


class GeoImportTests(unittest.TestCase):
    """Exercise provider ranges, empty countries and atomic rejection of bad archives."""

    def test_ranges_and_gap(self):
        """Produce identical inclusive ranges for both clients and omit non-catalogue countries."""
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            source = root / "db.csv.gz"
            output = root / "geo"
            source.write_bytes(
                gzip.compress(
                    b"1.1.1.0,1.1.1.3,AU\n1.1.1.4,1.1.1.7,ZZ\n2001:123::,2001:123::1,RU\n"
                )
            )
            import_geoip.build_dataset(source, output)
            self.assertEqual(
                json.loads((output / "manifest.json").read_bytes()),
                {"countries": ["AU", "RU"]},
            )
            self.assertEqual(
                json.loads((output / "RU.json").read_bytes())["rules"],
                [{"ip_cidr": ["2001:123::/127"]}],
            )
            index = (output / "country.bin").read_bytes()
            self.assertEqual(index[:8], b"HGI1" + struct.pack(">I", 1))
            self.assertEqual(index[8:18], bytes.fromhex("0101010001010103") + b"AU")
            self.assertEqual(
                index[18:],
                bytes.fromhex("20010123" + "00" * 12 + "20010123" + "00" * 11 + "01")
                + b"RU",
            )
            with self.assertRaises(ValueError):
                import_geoip.build_dataset(source, output)
            self.assertEqual(index, (output / "country.bin").read_bytes())

    def test_overlap(self):
        """Reject an overlapping range without publishing either derivative."""
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            source = root / "db.csv.gz"
            source.write_bytes(
                gzip.compress(b"1.1.1.0,1.1.1.3,AU\n1.1.1.3,1.1.1.5,RU\n")
            )
            with self.assertRaises(ValueError):
                import_geoip.build_dataset(source, root / "geo")
            self.assertFalse((root / "geo").exists())
