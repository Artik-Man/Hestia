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


def selector(group: dict, default: str) -> dict:
    """Build one selector with its preserved bootstrap exit and a deny fallback."""
    result = {
        "type": "selector",
        "tag": group["id"],
        "outbounds": [*group["exits"], "deny"],
        "default": default,
    }
    if "defaultExit" not in group:
        result["interrupt_exist_connections"] = True
    return result


def compile_inbound(item: dict) -> dict:
    """Validate and preserve one supported SOCKS or TUN inbound without changing its network settings."""
    require(isinstance(item, dict), "expected inbound object")
    kind = item.get("type")
    if kind == "tun":
        fields(item, "type tag interface_name address mtu auto_route stack")
        identifier(item["tag"])
        require(
            isinstance(item["interface_name"], str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", item["interface_name"]),
            "invalid TUN interface name",
        )
        require(
            isinstance(item["address"], list)
            and item["address"]
            and all(
                str(ipaddress.ip_interface(value)) == value
                for value in item["address"]
            ),
            "invalid TUN address",
        )
        require(type(item["mtu"]) is int and 576 <= item["mtu"] <= 9000, "invalid TUN MTU")
        require(item["auto_route"] is False and item["stack"] in {"system", "gvisor", "mixed"}, "unsupported TUN routing mode")
        return dict(item)
    if kind == "socks":
        fields(item, "type tag listen listen_port")
        identifier(item["tag"])
        require(item["listen"] in {"127.0.0.1", "::1"}, "SOCKS inbound must listen locally")
        number = port(item["listen_port"])
        require(number >= 1024 and number != 9090, "invalid SOCKS port")
        return dict(item)
    raise ValueError("unsupported inbound type")


def semantic_backend(backend: dict) -> dict:
    """Return routing-relevant backend fields for formatting-independent adoption comparisons."""
    require(isinstance(backend, dict), "expected backend object")
    return {
        key: backend.get(key)
        for key in ("experimental", "inbounds", "outbounds", "endpoints", "dns", "route")
        if key in backend
    }


def semantically_equal_backend(first: dict, second: dict) -> bool:
    """Compare backend behavior independently of JSON object key order and whitespace."""
    return semantic_backend(first) == semantic_backend(second)


def compare_backend_files(candidate: Path, installed: Path) -> None:
    """Require a staged candidate backend to match an installed backend's routing semantics."""
    first = json.loads(candidate.read_bytes(), object_pairs_hook=unique)
    second = json.loads(installed.read_bytes(), object_pairs_hook=unique)
    require(
        semantically_equal_backend(first, second),
        "candidate backend semantics differ from installed backend",
    )


def awg_metadata(directory: Path, connector_id: str) -> dict:
    """Load one root-private connector metadata file without reading or returning its secret profile."""
    identifier(connector_id)
    path = directory / "awg" / connector_id / "metadata.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, "invalid connector metadata file")
            raw = stream.read(4097)
            require(len(raw) <= 4096, "connector metadata is too large")
            result = json.loads(raw, object_pairs_hook=unique)
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("missing or invalid connector metadata") from None
    fields(result, "id group priority status ipv6Blocked type ipv4Address dnsIPv4")
    require(
        result["id"] == connector_id
        and identifier(result["group"])
        and type(result["priority"]) is int
        and result["priority"] > 0
        and result["status"] in {"configured", "ready"}
        and result["type"] in {"wireguard", "amneziawg"}
        and type(result["ipv6Blocked"]) is bool,
        "invalid connector metadata",
    )
    try:
        address = ipaddress.IPv4Interface(result["ipv4Address"])
        dns = ipaddress.IPv4Address(result["dnsIPv4"])
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
        raise ValueError("invalid connector IPv4 metadata") from None
    result["ipv4Address"] = str(address)
    result["dnsIPv4"] = str(dns)
    return result


def connector_outbounds(connectors: list[dict], directory: Path) -> tuple[list[dict], list[dict]]:
    """Build deterministic marked direct outbounds and DNS detours for validated AWG connectors."""
    outbounds, servers = [], []
    for connector in connectors:
        metadata = awg_metadata(directory, connector["id"])
        require(
            metadata["group"] == connector["group"]
            and metadata["priority"] == connector["priority"]
            and metadata["type"] == connector["type"]
            and metadata["ipv6Blocked"] == connector["ipv6Blocked"],
            "connector metadata differs from the profile",
        )
        outbounds.append(
            {
                "type": "direct",
                "tag": connector["id"],
                "bind_interface": "awg0",
                "routing_mark": 514,
            }
        )
        servers.append(
            {
                "type": "udp",
                "tag": "dns-" + connector["id"],
                "server": metadata["dnsIPv4"],
                "detour": connector["id"],
            }
        )
    return outbounds, servers


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
    require(
        isinstance(profile, dict)
        and type(profile.get("version")) is int
        and profile["version"] in {1, 2},
        "unsupported profile version",
    )
    managed_v2 = False
    if profile["version"] == 1:
        fields(profile, "version interfaces groups lists healthy socks_port")
        connectors = []
    else:
        managed_v2 = "inbounds" in profile
        if managed_v2:
            fields(profile, "version interfaces connectors groups lists healthy inbounds")
        else:
            fields(profile, "version interfaces connectors groups lists healthy socks_port")
        connectors = profile["connectors"]
        require(isinstance(connectors, list) and len(connectors) <= 64, "invalid connector list")
        require(sum(connector.get("status") == "ready" for connector in connectors) <= 1, "only one AWG connector can be active")
    listen = None
    if not managed_v2:
        listen = port(profile["socks_port"])
        require(listen >= 1024 and listen != 9090, "invalid SOCKS port")
    else:
        require(isinstance(profile["inbounds"], list), "expected inbounds array")
    groups, lists, health = (profile[k] for k in ("groups", "lists", "healthy"))
    require(
        all(isinstance(x, list) for x in (profile["interfaces"], groups, lists))
        and groups,
        "expected arrays and at least one group",
    )
    endpoints, servers, direct_outbounds, exits = [], [], [], set()
    for interface in profile["interfaces"]:
        require(isinstance(interface, dict), "expected interface object")
        if interface.get("type") == "direct":
            fields(interface, "id type bind_interface")
            tag = identifier(interface["id"])
            require(
                isinstance(interface["bind_interface"], str)
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface["bind_interface"]),
                "invalid direct interface binding",
            )
            endpoint, server = None, None
            direct_outbounds.append(
                {
                    "type": "direct",
                    "tag": tag,
                    "bind_interface": interface["bind_interface"],
                }
            )
        else:
            endpoint, server = wireguard(interface, directory)
            tag = endpoint["tag"]
            require(interface["type"] == "wireguard", "invalid interface type")
        require(tag not in exits and tag != "deny", "invalid or duplicate interface")
        exits.add(tag)
        if endpoint is not None:
            endpoints.append(endpoint)
            servers.append(server)
    connector_ids = set()
    for connector in connectors:
        fields(connector, "id type group priority ipv6Blocked status")
        tag = identifier(connector["id"])
        require(
            connector["type"] in {"wireguard", "amneziawg"}
            and identifier(connector["group"])
            and type(connector["priority"]) is int
            and connector["priority"] > 0
            and type(connector["ipv6Blocked"]) is bool
            and connector["status"] in {"configured", "ready"}
            and tag not in exits | connector_ids | {"deny"},
            "invalid or duplicate connector",
        )
        connector_ids.add(tag)
        exits.add(tag)
    rank, assigned = {}, set()
    outbounds = [{"type": "block", "tag": "deny"}]
    for index, group in enumerate(groups):
        if managed_v2:
            fields(group, "id exits defaultExit")
        else:
            fields(group, "id exits")
        tag = identifier(group["id"])
        require(
            tag not in exits | {"deny"} and tag not in rank,
            "duplicate or reserved group",
        )
        rank[tag] = index
        members = group["exits"]
        require(isinstance(members, list), "expected exits array")
        default_exit = group.get("defaultExit", "deny")
        require(default_exit == "deny" or default_exit in members, "default exit must belong to its group")
        expected_connectors = sorted(
            (item for item in connectors if item["group"] == tag),
            key=lambda item: item["priority"],
        )
        require(
            [item["id"] for item in expected_connectors]
            == [member for member in members if member in connector_ids],
            "connector order differs from the group",
        )
        for connector in expected_connectors:
            require(
                connector["priority"] <= len(members)
                and members[connector["priority"] - 1] == connector["id"],
                "invalid connector priority",
            )
        for member in members:
            require(
                member in exits and member not in assigned, "unknown or repeated exit"
            )
            assigned.add(member)
        outbounds.append(selector(group, default_exit))
    require(assigned == exits, "each interface must belong to one group")
    require(
        isinstance(health, dict)
        and all(k in exits and type(v) is bool for k, v in health.items()),
        "invalid availability",
    )
    require(
        all(
            (connector["status"] == "ready") == (health.get(connector["id"]) is True)
            for connector in connectors
        ),
        "connector readiness differs from availability",
    )
    routes = domain_routes(lists, rank)
    awg_outbounds, awg_servers = connector_outbounds(connectors, directory)
    inbounds = (
        [compile_inbound(item) for item in profile["inbounds"]]
        if managed_v2
        else [{"type": "socks", "listen": "127.0.0.1", "listen_port": listen}]
    )
    inbound_tags = {item.get("tag") for item in inbounds if "tag" in item}
    require(
        len(inbound_tags) == sum("tag" in item for item in inbounds)
        and not (inbound_tags & exits),
        "duplicate inbound tag",
    )
    route = {"final": groups[0]["id"]}
    if routes:
        route["rules"] = routes
    backend = {
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
        "inbounds": inbounds,
        "outbounds": [*outbounds, *direct_outbounds, *awg_outbounds],
        "route": route,
    }
    if managed_v2 and direct_outbounds:
        backend["outbounds"] = [
            *(item for item in outbounds if item["type"] == "selector"),
            *direct_outbounds,
            *awg_outbounds,
            next(item for item in outbounds if item["tag"] == "deny"),
        ]
    if endpoints:
        backend["endpoints"] = endpoints
    servers.extend(awg_servers)
    if servers:
        backend["dns"] = {"servers": servers, "strategy": "ipv4_only"}
    snapshot_groups = [{"id": group["id"], "exits": group["exits"]} for group in groups]
    snapshot = {"groups": snapshot_groups, "lists": lists, "healthy": health}
    if profile["version"] == 2 and connectors:
        snapshot["connectorKinds"] = {connector["id"]: "awg" for connector in connectors}
    return snapshot, backend


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


def replace_private(path: Path, data: bytes) -> None:
    """Replace one private staged metadata file through an exclusive sibling and atomic rename."""
    temporary = path.with_name(path.name + ".next")
    write_private(temporary, data)
    os.replace(temporary, path)


def managed_profile(base: Path) -> tuple[dict, dict, dict]:
    """Read the verified installed profile and its matching snapshot and backend without reopening VPN sources."""
    profile = read_verified(base, "profile.json", "profile-source.sha256")
    require(type(profile.get("version")) is int and profile["version"] in {1, 2}, "unsupported profile")
    managed_v2 = False
    if profile["version"] == 1:
        fields(profile, "version interfaces groups lists healthy socks_port")
        connectors = []
    else:
        managed_v2 = "inbounds" in profile
        if managed_v2:
            fields(profile, "version interfaces connectors groups lists healthy inbounds")
        else:
            fields(profile, "version interfaces connectors groups lists healthy socks_port")
        connectors = profile["connectors"]
        require(isinstance(connectors, list), "invalid connector metadata")
    backend = read_verified(base, "sing-box.json", "profile-backend.sha256")
    snapshot = json.loads(
        (base / "snapshot.json").read_bytes(), object_pairs_hook=unique
    )
    if profile["version"] == 2 and connectors:
        fields(snapshot, "groups lists healthy connectorKinds")
    else:
        fields(snapshot, "groups lists healthy")
    profile_groups = [
        {"id": group["id"], "exits": group["exits"]} for group in profile["groups"]
    ]
    require(
        snapshot["groups"] == profile_groups and snapshot["lists"] == profile["lists"],
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
    if profile["version"] == 2 and connectors:
        require(
            snapshot["connectorKinds"]
            == {connector["id"]: "awg" for connector in connectors},
            "snapshot connector kinds differ from the installed profile",
        )
    lists = profile["lists"]
    route_default = groups[0]["id"]
    expected_route = {"final": route_default}
    if domain_routes(lists, rank):
        expected_route["rules"] = domain_routes(lists, rank)
    require(
        backend["route"]
        == expected_route,
        "backend routes differ from the installed profile",
    )
    connector_routes, connector_servers = connector_outbounds(connectors, base)
    if connector_routes:
        require(
            [item for item in backend["outbounds"] if item.get("tag") in {route["tag"] for route in connector_routes}]
            == connector_routes,
            "backend AWG outbounds differ from connector metadata",
        )
        servers = backend.get("dns", {}).get("servers", [])
        require(
            servers[-len(connector_servers) :] == connector_servers,
            "backend AWG DNS differs from connector metadata",
        )
    if managed_v2:
        _, expected = compile_profile(profile, base)
        require(
            semantically_equal_backend(expected, backend),
            "backend semantics differ from the managed profile",
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
    desired_groups = []
    for group in groups:
        previous = next(item for item in old if item["id"] == group["id"])
        default = previous.get("defaultExit", "deny")
        if default not in group["exits"]:
            default = group["exits"][0] if "inbounds" in profile and group["exits"] else "deny"
        desired_groups.append({"id": group["id"], "exits": group["exits"], **({"defaultExit": default} if "inbounds" in profile else {})})
    deny = {"type": "block", "tag": "deny"}
    direct_routes = [
        {
            "type": "direct",
            "tag": item["id"],
            "bind_interface": item["bind_interface"],
        }
        for item in profile["interfaces"]
        if item["type"] == "direct"
    ]
    connector_routes, _ = connector_outbounds(profile.get("connectors", []), base)
    require(
        backend["outbounds"]
        == (
            [*(selector(g, g.get("defaultExit", "deny")) for g in old), *direct_routes, *connector_routes, deny]
            if "inbounds" in profile and direct_routes
            else [deny, *(selector(g, g.get("defaultExit", "deny")) for g in old), *direct_routes, *connector_routes]
        ),
        "unexpected selector topology",
    )
    backend["outbounds"] = (
        [*(selector(g, g.get("defaultExit", "deny")) for g in desired_groups), *direct_routes, *connector_routes, deny]
        if "inbounds" in profile and direct_routes
        else [deny, *(selector(g, g.get("defaultExit", "deny")) for g in desired_groups), *direct_routes, *connector_routes]
    )
    connectors = profile.get("connectors", [])
    for connector in connectors:
        group = next((item for item in groups if item["id"] == connector["group"]), None)
        require(group is not None and connector["id"] in group["exits"], "connector order is incomplete")
        connector["priority"] = group["exits"].index(connector["id"]) + 1
        metadata_path = stage / "awg" / connector["id"] / "metadata.json"
        metadata = awg_metadata(stage, connector["id"])
        metadata["priority"] = connector["priority"]
        replace_private(metadata_path, json.dumps(metadata, separators=(",", ":")).encode())
    connector_routes, _ = connector_outbounds(connectors, stage)
    ordered_routes = domain_routes(
        profile["lists"], {group["id"]: i for i, group in enumerate(groups)}
    )
    backend["route"] = {"final": desired_groups[0]["id"]}
    if ordered_routes:
        backend["route"]["rules"] = ordered_routes
    profile["groups"] = desired_groups
    snapshot["groups"] = [{"id": group["id"], "exits": group["exits"]} for group in desired_groups]
    stage_generation(stage, profile, snapshot, backend)


def main() -> None:
    """Write both validated configurations to new files inside the private staging directory."""
    if len(sys.argv) == 4 and sys.argv[1] == "--compare-backend":
        compare_backend_files(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--validate-managed":
        managed_profile(Path(sys.argv[2]))
        return
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
