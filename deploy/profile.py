"""Compile a versioned stand profile into private staging files for the installer."""

import base64
import configparser
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    """Reject a profile when a required invariant is false."""
    if not condition:
        raise ValueError(message)


def fields(obj: dict, names: str) -> None:
    """Require exactly the listed keys; unknown settings must not be silently ignored."""
    require(
        isinstance(obj, dict) and set(obj) == set(names.split()),
        "unexpected or missing fields: expected " + names,
    )


def identifier(value: str) -> str:
    """Return a validated routing tag suitable for a selector or group."""
    require(
        isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value),
        "invalid identifier",
    )
    return value


def key(value: str) -> str:
    """Validate the base64 encoding and 32-byte length of a WireGuard key."""
    require(
        isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32,
        "invalid WireGuard key",
    )
    return value


def port(value: int) -> int:
    """Return a valid transport port, excluding booleans and out-of-range numbers."""
    require(type(value) is int and 1 <= value <= 65535, "invalid port")
    return value


def unique(pairs: list) -> dict:
    """Reject duplicate JSON object fields before one can overwrite another."""
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def asset(directory: Path, reference: str) -> str:
    """Read one bounded, regular sibling file without following a symlink."""
    require(
        isinstance(reference, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", reference),
        "expected a sibling filename",
    )
    try:
        fd = os.open(directory / reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "not a regular file")
            data = stream.read(65537)
            require(len(data) <= 65536, "file too large")
            return data.decode("utf-8")
    except (OSError, ValueError) as error:
        raise ValueError(f"missing or unreadable VPN file: {reference}") from error


def wireguard(interface: dict, directory: Path) -> tuple[dict, dict]:
    """Compile a single-peer VPN file into an endpoint and a DNS server using that endpoint."""
    optional = " private_key_file" if "private_key_file" in interface else ""
    fields(interface, "id type config_file" + optional)
    tag = identifier(interface["id"])
    cfg = configparser.ConfigParser(interpolation=None, delimiters=("=",))
    try:
        cfg.read_string(asset(directory, interface["config_file"]))
    except configparser.Error:
        raise ValueError("malformed WireGuard file") from None
    require(
        not cfg.defaults() and set(cfg.sections()) == {"Interface", "Peer"},
        "expected one WireGuard peer",
    )
    local, peer = cfg["Interface"], cfg["Peer"]
    required = {"address", "dns"} if optional else {"address", "dns", "privatekey"}
    require(
        set(local) == required and set(peer) == {"publickey", "endpoint", "allowedips"},
        "unsupported WireGuard settings",
    )
    private = (
        asset(directory, interface["private_key_file"]).strip()
        if optional
        else local["privatekey"]
    )
    ip, sep, number = peer["endpoint"].rpartition(":")
    require(sep and number.isdecimal(), "expected IPv4:port endpoint")
    allowed = [
        str(ipaddress.IPv4Network(item.strip()))
        for item in peer["allowedips"].split(",")
    ]
    endpoint = {
        "type": "wireguard",
        "tag": tag,
        "system": False,
        "address": [str(ipaddress.IPv4Interface(local["address"]))],
        "private_key": key(private),
        "domain_resolver": "dns-" + tag,
        "peers": [
            {
                "address": str(ipaddress.IPv4Address(ip)),
                "port": port(int(number)),
                "public_key": key(peer["publickey"]),
                "allowed_ips": allowed,
            }
        ],
    }
    server = {
        "type": "udp",
        "tag": "dns-" + tag,
        "server": str(ipaddress.IPv4Address(local["dns"])),
        "detour": tag,
    }
    return endpoint, server


def domain_routes(lists: list, rank: dict[str, int]) -> list[dict]:
    """Compile domain bindings in routing priority order, preserving unassigned lists in the profile."""
    rules, seen = [], set()
    for item in lists:
        fields(item, "id group masks")
        name, tag = identifier(item["id"]), item["group"]
        require(
            name not in seen and (tag == "" or tag in rank),
            "unknown group or duplicate list",
        )
        seen.add(name)
        require(isinstance(item["masks"], list), "expected masks array")
        for mask in item["masks"]:
            require(
                isinstance(mask, str) and mask.startswith("*."), "expected *.suffix"
            )
            suffix = mask[2:].removesuffix(".").lower()
            labels = suffix.split(".")
            require(
                len(suffix) <= 253
                and all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s)
                    for s in labels
                ),
                "invalid domain suffix",
            )
            if tag:
                rules.append((-len(labels), rank[tag], suffix, tag))
    return [
        {"domain_suffix": suffix, "action": "route", "outbound": tag}
        for _, _, suffix, tag in sorted(rules)
    ]


def selector(group: dict) -> dict:
    """Build one selector that initially denies traffic until the controller chooses a healthy member."""
    return {
        "type": "selector",
        "tag": group["id"],
        "outbounds": [*group["exits"], "deny"],
        "default": "deny",
        "interrupt_exist_connections": True,
    }


def compile_profile(profile: dict, directory: Path) -> tuple[dict, dict]:
    """Validate a stand profile and derive the matching controller snapshot and sing-box configuration."""
    if (
        profile == {"version": 1, "mode": "bootstrap"}
        and type(profile["version"]) is int
    ):
        return (
            {"groups": [{"id": "bootstrap", "exits": []}], "lists": [], "healthy": {}},
            {
                "experimental": {
                    "clash_api": {"external_controller": "127.0.0.1:9090"}
                },
                "inbounds": [],
                "outbounds": [
                    {
                        "type": "selector",
                        "tag": "bootstrap",
                        "outbounds": ["deny"],
                        "default": "deny",
                    },
                    {"type": "direct", "tag": "deny", "bind_interface": "lo"},
                ],
                "route": {"rules": [{"action": "reject"}]},
            },
        )
    fields(profile, "version interfaces groups lists healthy socks_port")
    require(
        type(profile["version"]) is int and profile["version"] == 1,
        "unsupported profile version",
    )
    listen = port(profile["socks_port"])
    require(listen >= 1024 and listen != 9090, "invalid SOCKS port")
    groups, lists, health = (profile[k] for k in ("groups", "lists", "healthy"))
    require(
        all(isinstance(x, list) for x in (profile["interfaces"], groups, lists))
        and groups,
        "expected arrays and at least one group",
    )
    endpoints, servers, exits = [], [], set()
    for interface in profile["interfaces"]:
        endpoint, server = wireguard(interface, directory)
        tag = endpoint["tag"]
        require(
            tag not in exits and tag != "deny" and interface["type"] == "wireguard",
            "invalid or duplicate interface",
        )
        exits.add(tag)
        endpoints.append(endpoint)
        servers.append(server)
    rank, assigned = {}, set()
    outbounds = [{"type": "block", "tag": "deny"}]
    for index, group in enumerate(groups):
        fields(group, "id exits")
        tag = identifier(group["id"])
        require(
            tag not in exits | {"deny"} and tag not in rank,
            "duplicate or reserved group",
        )
        rank[tag] = index
        members = group["exits"]
        require(isinstance(members, list), "expected exits array")
        for member in members:
            require(
                member in exits and member not in assigned, "unknown or repeated exit"
            )
            assigned.add(member)
        outbounds.append(selector(group))
    require(assigned == exits, "each interface must belong to one group")
    require(
        isinstance(health, dict)
        and all(k in exits and type(v) is bool for k, v in health.items()),
        "invalid availability",
    )
    routes = domain_routes(lists, rank)
    backend = {
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": listen}],
        "outbounds": outbounds,
        "endpoints": endpoints,
        "route": {"rules": routes, "final": groups[0]["id"]},
    }
    if servers:
        backend["dns"] = {"servers": servers, "strategy": "ipv4_only"}
    return {"groups": groups, "lists": lists, "healthy": health}, backend


def read_verified(base: Path, name: str, checksum: str) -> dict:
    """Load a managed JSON object after checking its installer-recorded SHA-256 digest."""
    raw = (base / name).read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == (base / checksum).read_text().strip(),
        "installed file differs from its validated digest",
    )
    return json.loads(raw, object_pairs_hook=unique)


def write_private(path: Path, data: bytes) -> None:
    """Create one private staging file exclusively and write its contents."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def managed_profile(base: Path) -> tuple[dict, dict, dict]:
    """Read the verified installed profile and its matching snapshot and backend without reopening VPN sources."""
    profile = read_verified(base, "profile.json", "profile-source.sha256")
    fields(profile, "version interfaces groups lists healthy socks_port")
    require(
        type(profile["version"]) is int and profile["version"] == 1,
        "unsupported profile",
    )
    backend = read_verified(base, "sing-box.json", "profile-backend.sha256")
    snapshot = json.loads(
        (base / "snapshot.json").read_bytes(), object_pairs_hook=unique
    )
    fields(snapshot, "groups lists healthy")
    require(
        all(snapshot[name] == profile[name] for name in ("groups", "lists")),
        "snapshot topology differs from the installed profile",
    )
    groups = profile["groups"]
    rank = {group["id"]: i for i, group in enumerate(groups)}
    require(bool(groups), "empty group topology")
    exits = {tag for group in groups for tag in group["exits"]}
    health = snapshot["healthy"]
    require(
        isinstance(health, dict)
        and all(k in exits and type(v) is bool for k, v in health.items()),
        "invalid availability",
    )
    lists = profile["lists"]
    require(
        backend["route"]
        == {"rules": domain_routes(lists, rank), "final": groups[0]["id"]},
        "backend routes differ from the installed profile",
    )
    return profile, snapshot, backend


def stage_generation(stage: Path, profile: dict, snapshot: dict, backend: dict) -> None:
    """Write the complete private candidate and both verification digests into an empty staging directory."""
    for name, checksum, obj in (
        ("profile.json", "profile-source.sha256", profile),
        ("sing-box.json", "profile-backend.sha256", backend),
        ("snapshot.json", None, snapshot),
    ):
        raw = json.dumps(obj, indent=2).encode()
        write_private(stage / name, raw)
        if checksum is not None:
            write_private(
                stage / checksum, (hashlib.sha256(raw).hexdigest() + "\n").encode()
            )


def stage_binding(base: Path, stage: Path, list_id: str, group_id: str) -> None:
    """Stage a list binding under the installer lock without reimporting secret VPN assets."""
    profile, snapshot, backend = managed_profile(base)
    rank = {group["id"]: i for i, group in enumerate(profile["groups"])}
    require(group_id == "" or group_id in rank, "unknown group")
    lists = profile["lists"]
    item = next((entry for entry in lists if entry["id"] == list_id), None)
    require(item is not None, "unknown list")
    item["group"] = group_id
    backend["route"]["rules"] = domain_routes(lists, rank)
    snapshot["lists"] = lists
    stage_generation(stage, profile, snapshot, backend)


def stage_order(base: Path, stage: Path, groups: list[dict]) -> None:
    """Apply a complete within-group permutation to selector order, tie-breaking rules and the default route."""
    profile, snapshot, backend = managed_profile(base)
    old = profile["groups"]
    members = {group["id"]: sorted(group["exits"]) for group in old}
    require(
        isinstance(groups, list) and len(groups) == len(old), "incomplete group order"
    )
    for group in groups:
        fields(group, "id exits")
        group_id = identifier(group["id"])
        require(
            isinstance(group["exits"], list) and group_id in members,
            "unknown or repeated group",
        )
        require(
            sorted(group["exits"]) == members.pop(group_id), "changed group membership"
        )
    deny = {"type": "block", "tag": "deny"}
    require(
        backend["outbounds"] == [deny, *(selector(g) for g in old)],
        "unexpected selector topology",
    )
    backend["outbounds"] = [deny, *(selector(g) for g in groups)]
    backend["route"] = {
        "final": groups[0]["id"],
        "rules": domain_routes(
            profile["lists"], {group["id"]: i for i, group in enumerate(groups)}
        ),
    }
    profile["groups"] = snapshot["groups"] = groups
    stage_generation(stage, profile, snapshot, backend)


def main() -> None:
    """Write both validated configurations to new files inside the private staging directory."""
    if len(sys.argv) == 6 and sys.argv[1] == "--rebind":
        stage_binding(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--reorder":
        stage = Path(sys.argv[3])
        groups = json.loads(
            (stage / "desired-order.json").read_bytes(), object_pairs_hook=unique
        )
        stage_order(Path(sys.argv[2]), stage, groups)
        return
    profile, destination = map(Path, sys.argv[1:3])
    directory = Path(sys.argv[3]) if len(sys.argv) == 4 else profile.parent
    snapshot, backend = compile_profile(
        json.loads(profile.read_text(), object_pairs_hook=unique), directory
    )
    os.umask(0o077)
    for name, data in (("snapshot", snapshot), ("sing-box", backend)):
        with (destination / (name + ".json")).open("x") as output:
            json.dump(data, output, indent=2)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError) as error:
        detail = str(error)
        if detail.startswith("missing or unreadable VPN file: "):
            sys.exit(detail)
        sys.exit(
            "Invalid deployment profile: check fields, addresses, file references and keys"
        )
