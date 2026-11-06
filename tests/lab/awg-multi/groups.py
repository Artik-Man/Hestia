"""Compile two connector outbounds with the shipping compiler and attach local group probes."""

import json
import runpy
import sys
from pathlib import Path


def write_config(compiler: Path, target: Path) -> None:
    """Use the stored metadata for two profiles to build independent SOCKS ingress paths through their group selectors."""
    implementation = runpy.run_path(str(compiler))
    base = Path("/etc/hestia")
    ids = ("tunnel-a", "tunnel-b")
    connectors = [implementation["awg_metadata"](base, tag) for tag in ids]
    outbounds, servers = implementation["connector_outbounds"](connectors, base)
    config = {"log": {"level": "error"}, "dns": {"servers": servers}, "inbounds": [],
              "outbounds": outbounds + [{"type": "block", "tag": "deny"}],
              "route": {"rules": []}}
    for index, tag in enumerate(ids):
        ingress, group = f"client-{index}", f"group-{index}"
        config["inbounds"].append({"type": "socks", "tag": ingress, "listen": "127.0.0.1", "listen_port": 20080 + index})
        config["outbounds"].append(implementation["selector"]({"id": group, "exits": [tag]}, tag))
        config["route"]["rules"].append({"inbound": [ingress], "action": "route", "outbound": group})
    target.write_text(json.dumps(config))


if __name__ == "__main__":
    write_config(Path(sys.argv[1]), Path(sys.argv[2]))
