"""Build a journal lookup and sing-box source rule sets from one DB-IP Country Lite CSV.gz."""

import argparse
import csv
import gzip
import ipaddress
import json
import os
import struct
import tempfile
from pathlib import Path

COUNTRIES = Path(__file__).resolve().parents[1] / "backend/internal/geoip/countries.txt"


def build_dataset(source, destination):
    """Publish a new immutable directory; reject invalid or overlapping source ranges."""
    codes = set(COUNTRIES.read_text(encoding="ascii").split())
    if destination.exists():
        raise ValueError("output directory already exists")
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        output = Path(work) / "dataset"
        output.mkdir()
        prefixes = {}
        last_end = {}
        ipv4_count = 0
        family = 4
        with (
            gzip.open(source, "rt", encoding="ascii", newline="") as rows,
            (output / "country.bin").open("wb") as index,
        ):
            index.write(b"HGI1" + bytes(4))
            for raw_start, raw_end, code in csv.reader(rows):
                start = ipaddress.ip_address(raw_start)
                end = ipaddress.ip_address(raw_end)
                if (
                    start.version != end.version
                    or start > end
                    or start.version < family
                    or int(start) <= last_end.get(start.version, -1)
                ):
                    raise ValueError("invalid, overlapping or unordered country range")
                family = start.version
                last_end[family] = int(end)
                # DB-IP includes special ranges (ZZ) and Kosovo (XK) outside the panel catalogue.
                if code in ("ZZ", "XK"):
                    continue
                if code not in codes:
                    raise ValueError(f"unexpected country code {code!r}")
                index.write(start.packed + end.packed + code.encode("ascii"))
                ipv4_count += family == 4
                prefixes.setdefault(code, []).extend(
                    str(prefix)
                    for prefix in ipaddress.summarize_address_range(start, end)
                )
            if not prefixes:
                raise ValueError("no supported country ranges")
            index.seek(4)
            index.write(struct.pack(">I", ipv4_count))
        for code, cidrs in prefixes.items():
            rules = {"version": 3, "rules": [{"ip_cidr": cidrs}]}
            (output / f"{code}.json").write_text(
                json.dumps(rules, separators=(",", ":")), encoding="ascii"
            )
        manifest = {"countries": sorted(prefixes)}
        (output / "manifest.json").write_text(json.dumps(manifest), encoding="ascii")
        os.rename(output, destination)


def main():
    """Read the provider archive and build an installable dataset in a fresh directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    build_dataset(args.source, args.destination)


if __name__ == "__main__":
    main()
