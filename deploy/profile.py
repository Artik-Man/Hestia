"""Compile a versioned stand profile into private staging files for the installer."""

import base64
import configparser
import hashlib
import hmac
import tempfile
import ipaddress
import json
import os
import re
import stat
import sys
import unicodedata
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


def connection_id(value: str) -> str:
    """Accept a stable connector UUID or a legacy routing tag for an installed exit."""
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        return value
    return identifier(value)


def group_name(value: str) -> str:
    """Return a valid group display name, preserving its Unicode text and internal spaces."""
    require(
        isinstance(value, str) and 1 <= len(value) <= 80 and value.strip() == value
        and all(unicodedata.category(char) not in {"Cc", "Cs"} for char in value),
        "invalid group display name",
    )
    return value


def snapshot_group(group: dict) -> dict:
    """Project the public group fields and preserve an explicitly supplied display name."""
    result = {"id": group["id"], "exits": group["exits"]}
    if "name" in group:
        result["name"] = group_name(group["name"])
    return result


def unique_group_names(groups: list[dict]) -> None:
    """Require distinct visible names, including routing IDs displayed by older profiles."""
    names = [group.get("name", group["id"]) for group in groups]
    require(len(set(names)) == len(names), "duplicate group display name")


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
        fields(item, "id group masks name" if "name" in item else "id group masks")
        if "name" in item:
            group_name(item["name"])
        name, tag = identifier(item["id"]), item["group"]
        require(
            name not in seen and (tag == "" or tag in rank),
            "unknown group or duplicate list",
        )
        seen.add(name)
        require(isinstance(item["masks"], list), "expected masks array")
        for mask in item["masks"]:
            require(
                isinstance(mask, str) and mask.isascii() and mask.startswith("*."),
                "expected ASCII *.suffix",
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
    connection_id(connector_id)
    path = directory / "awg" / connector_id / "metadata.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, "invalid connector metadata file")
            raw = stream.read(8193)
            require(len(raw) <= 8192, "connector metadata is too large")
            result = json.loads(raw, object_pairs_hook=unique)
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("missing or invalid connector metadata") from None
    fields(result, "id group priority status ipv6Blocked type ipv4Address dnsIPv4" + (" slot" if "slot" in result else "") + (" underlays" if "underlays" in result else "") + (" name" if "name" in result else ""))
    if "name" in result:
        group_name(result["name"])
    connector_slot(result)
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


def validate_underlays(profile: dict) -> None:
    """Reject invalid transport choices, including cycles through any lower-priority candidate."""
    nodes = {item["id"]: [] for item in profile["interfaces"]}
    for connector in profile.get("connectors", []):
        choices = connector.get("underlays", [])
        require(isinstance(choices, list) and len(choices) <= 64, "invalid underlay list")
        for exit_id in choices:
            connection_id(exit_id)
        require(len(set(choices)) == len(choices), "repeated underlay")
        nodes[connector["id"]] = choices
    verified, visiting = set(), set()

    def visit(exit_id: str) -> None:
        """Check all outbound edges once, rejecting unknown and currently visited exits."""
        require(exit_id in nodes and exit_id not in visiting, "unknown or cyclic underlay")
        if exit_id in verified:
            return
        visiting.add(exit_id)
        for target in nodes[exit_id]:
            visit(target)
        visiting.remove(exit_id)
        verified.add(exit_id)

    for exit_id in nodes:
        visit(exit_id)


def connector_slot(connector: dict) -> int:
    """Validate the assigned slot; absent slot on an older profile defaults to zero."""
    slot = connector.get("slot", 0)
    require(type(slot) is int and 0 <= slot < 50, "invalid connector slot")
    return slot


def connector_outbounds(connectors: list[dict], directory: Path) -> tuple[list[dict], list[dict]]:
    """Build deterministic marked direct outbounds and DNS detours for validated AWG connectors."""
    outbounds, servers = [], []
    occupied: set[int] = set()
    for connector in connectors:
        metadata = awg_metadata(directory, connector["id"])
        require(
            metadata.get("name") == connector.get("name")
            and metadata["group"] == connector["group"]
            and metadata["priority"] == connector["priority"]
            and metadata["type"] == connector["type"]
            and metadata["ipv6Blocked"] == connector["ipv6Blocked"],
            "connector metadata differs from the profile",
        )
        require(connector.get("underlays", []) == metadata.get("underlays", []), "connector underlays differ from metadata")
        slot = connector_slot(connector)
        require(slot == connector_slot(metadata), "connector slot differs from metadata")
        require(connector["status"] == metadata["status"], "connector status differs from metadata")
        if connector["status"] == "ready" or slot != 0:
            require(slot not in occupied, "duplicate connector slot")
            occupied.add(slot)
        if connector["status"] == "ready":
            outbounds.append({
                "type": "direct", "tag": connector["id"],
                "bind_interface": f"awg{slot}", "routing_mark": 514 + slot,
                "domain_resolver": "dns-" + connector["id"],
            })
        else:
            outbounds.append({"type": "block", "tag": connector["id"]})
        servers.append(
            {
                "type": "udp",
                "tag": "dns-" + connector["id"],
                "server": metadata["dnsIPv4"],
                "detour": connector["id"],
            }
        )
    return outbounds, servers


UNDERLAY_DNS = {"type": "local", "tag": "hestia-underlay-resolver"}


def transport_fragments(profile: dict, directory: Path) -> tuple[list[dict], list[dict]]:
    """Pin each manual candidate to a loopback UDP port restricted to this tunnel's stored peer destination."""
    listeners, rules = [], []
    for connector in profile.get("connectors", []):
        candidates = connector.get("underlays", [])
        if connector["status"] != "ready" or not candidates:
            continue
        config = configparser.ConfigParser(interpolation=None, delimiters=("=",))
        try:
            config.read_string(asset(directory / "awg" / connection_id(connector["id"]), "profile.conf"))
            host, sep, number = config["Peer"]["Endpoint"].rpartition(":")
            require(sep and number.isdecimal() and host and ":" not in host, "invalid transport endpoint")
            peer_port = port(int(number))
        except (configparser.Error, KeyError, ValueError):
            raise ValueError("invalid stored transport endpoint") from None
        slot = connector_slot(connector)
        for index, candidate in enumerate(candidates):
            tag = f"_wg-transport-{slot}-{index}"
            listeners.append({"type": "direct", "tag": tag, "listen": "127.0.0.1",
                              "listen_port": 20000 + slot * 128 + index, "network": "udp"})
            rules.append({"inbound": [tag], "action": "route", "outbound": connection_id(candidate),
                          "override_address": host, "override_port": peer_port, "udp_connect": True})
    return listeners, rules


def quality_fragments(endpoints: list[dict], occupied: set) -> tuple[list[dict], list[dict]]:
    """Build authenticated loopback SOCKS paths to individual userspace WireGuard endpoints."""
    listeners, rules = [], []
    for index, endpoint in enumerate(endpoints):
        number = 27000 + index
        require(number <= 29999 and number not in occupied, "occupied quality probe port")
        exit_id = identifier(endpoint["tag"])
        tag = "_quality-" + exit_id
        password = hmac.new(base64.b64decode(endpoint["private_key"]),
                            ("hestia-quality/" + exit_id).encode(), hashlib.sha256).hexdigest()
        listeners.append({"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": number,
                          "users": [{"username": "hestia-quality", "password": password}]})
        rules.append({"inbound": [tag], "action": "route", "outbound": exit_id})
    return listeners, rules


def pinned_paths(backend: dict) -> list[dict]:
    """Extract confined egress transports without copying VPN private keys."""
    paths = [{"id": item["tag"], "device": item["bind_interface"], "mark": item.get("routing_mark", 0)}
             for item in backend.get("outbounds", []) if item["type"] == "direct"
             and item.get("bind_interface") and item["tag"] != "deny"]
    for item in backend.get("inbounds", []):
        if item.get("tag", "").startswith("_quality-") and item["type"] == "socks":
            paths.append({"id": item["tag"][9:], "socksAddress": "127.0.0.1:" + str(item["listen_port"]),
                          "socksPassword": item["users"][0]["password"]})
    return paths


def export_paths(backend: dict, directory: Path, source: os.stat_result | None = None) -> None:
    """Publish confined paths; DNS additionally gets per-exit resolvers and source generation."""
    paths = pinned_paths(backend)
    payload = paths
    if source is not None:
        resolvers = {item["detour"]: item["server"] for item in backend.get("dns", {}).get("servers", [])
                     if item.get("type") == "udp" and item.get("detour")}
        payload = {"inode": source.st_ino, "modified": source.st_mtime_ns, "paths": paths,
                   "resolvers": resolvers}
    owner = directory.stat()
    os.setgroups([])
    os.setgid(owner.st_gid)
    os.setuid(owner.st_uid)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False, mode="w") as stream:
        json.dump(payload, stream)
    os.replace(stream.name, directory / "paths.json")


def replace_domain_routes(backend: dict, final: str, rules: list[dict]) -> None:
    """Retain already verified tunnel transport bindings ahead of rewritten domain/group rules."""
    transports = [rule for rule in backend["route"].get("rules", [])
                  if any(tag.startswith(("_wg-transport-", "_quality-")) for tag in rule.get("inbound", []))]
    backend["route"] = {"final": final}
    if transports or rules:
        backend["route"]["rules"] = transports + rules


def bind_underlay_dns(outbounds: list[dict], servers: list[dict], manual: bool = False) -> None:
    """Keep direct underlay name lookups local when multiple tunnel DNS servers require explicit resolution."""
    if outbounds and (manual or len(servers) > 1):
        for outbound in outbounds:
            outbound["domain_resolver"] = UNDERLAY_DNS["tag"]
        servers.append(dict(UNDERLAY_DNS))


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
        fields(connector, "id type group priority ipv6Blocked status" + (" slot" if "slot" in connector else "") + (" underlays" if "underlays" in connector else "") + (" name" if "name" in connector else ""))
        if "name" in connector:
            group_name(connector["name"])
        tag = connection_id(connector["id"])
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
    validate_underlays(profile)
    rank, assigned = {}, set()
    outbounds = [{"type": "block", "tag": "deny"}]
    for index, group in enumerate(groups):
        group_fields = "id exits defaultExit" if managed_v2 else "id exits"
        fields(group, group_fields + (" name" if "name" in group else ""))
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
    transport_inbounds, transport_rules = transport_fragments(profile, directory)
    existing_ports = {item.get("listen_port") for item in inbounds}
    require(all(item["listen_port"] not in existing_ports for item in transport_inbounds), "occupied WireGuard transport port")
    quality_inbounds, quality_rules = quality_fragments(endpoints, existing_ports | {item["listen_port"] for item in transport_inbounds})
    inbounds += transport_inbounds + quality_inbounds
    routes = quality_rules + routes
    routes = transport_rules + routes
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
    if awg_servers:
        bind_underlay_dns(direct_outbounds, servers, bool(transport_rules))
    if servers:
        backend["dns"] = {"servers": servers, "strategy": "ipv4_only"}
    snapshot_groups = [snapshot_group(group) for group in groups]
    unique_group_names(snapshot_groups)
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
    profile_groups = [snapshot_group(group) for group in profile["groups"]]
    unique_group_names(profile_groups)
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
    transport_inbounds, transport_rules = transport_fragments(profile, base)
    require([item for item in backend.get("inbounds", []) if item.get("tag", "").startswith("_wg-transport-")]
            == transport_inbounds, "backend transport listeners differ from the selected underlays")
    quality_inbounds, quality_rules = quality_fragments(backend.get("endpoints", []),
        {item.get("listen_port") for item in backend.get("inbounds", []) if not item.get("tag", "").startswith("_quality-")})
    installed_quality = [item for item in backend.get("inbounds", []) if item.get("tag", "").startswith("_quality-")]
    if quality_inbounds and not installed_quality:
        # Upgrade only a known pre-quality generation, preserving endpoint keys and route order.
        legacy = transport_rules + domain_routes(lists, rank)
        require(backend["route"] == ({"final": route_default, "rules": legacy} if legacy else {"final": route_default}),
                "unexpected legacy routes")
        backend["inbounds"] += quality_inbounds
        backend["route"]["rules"] = transport_rules + quality_rules + domain_routes(lists, rank)
    else:
        require(installed_quality == quality_inbounds, "backend quality listeners differ from endpoints")
    expected_rules = transport_rules + quality_rules + domain_routes(lists, rank)
    if expected_rules:
        expected_route["rules"] = expected_rules
    require(
        backend["route"]
        == expected_route,
        "backend routes differ from the installed profile",
    )
    validate_underlays(profile)
    connector_routes, connector_servers = connector_outbounds(connectors, base)
    if connector_routes:
        # Normalize only the exact outbound emitted by v1 for an inactive legacy
        # profile. Staged generations then publish a blocked exit for that profile.
        legacy_inactive = {
            item["id"] for item in connectors if item["status"] == "configured" and "slot" not in item
        }
        legacy_ready = {item["id"] for item in connectors if item["status"] == "ready" and "slot" not in item}
        for i, item in enumerate(backend["outbounds"]):
            tag = item.get("tag")
            if tag in legacy_ready and item == {
                "type": "direct", "tag": tag, "bind_interface": "awg0", "routing_mark": 514,
            }:
                backend["outbounds"][i] = {**item, "domain_resolver": "dns-" + tag}
            if tag in legacy_inactive and item == {
                "type": "direct", "tag": tag, "bind_interface": "awg0", "routing_mark": 514,
            }:
                backend["outbounds"][i] = {"type": "block", "tag": tag}
        require(
            [item for item in backend["outbounds"] if item.get("tag") in {route["tag"] for route in connector_routes}]
            == connector_routes,
            "backend AWG outbounds differ from connector metadata",
        )
        servers = backend.get("dns", {}).get("servers", [])
        tunnel_servers = servers[:-1] if servers and servers[-1] == UNDERLAY_DNS else servers
        require(
            tunnel_servers[-len(connector_servers) :] == connector_servers,
            "backend AWG DNS differs from connector metadata",
        )
    if managed_v2:
        _, expected = compile_profile(profile, base)
        # Only upgrade the exact legacy direct bindings and DNS list. The full
        # semantic comparison below rejects unrelated additions or modifications.
        desired_servers = expected.get("dns", {}).get("servers", [])
        if desired_servers and desired_servers[-1] == UNDERLAY_DNS and all("slot" not in c for c in connectors):
            installed_servers = backend.get("dns", {}).get("servers", [])
            if installed_servers == desired_servers[:-1]:
                installed_servers.append(dict(UNDERLAY_DNS))
                for outbound in backend["outbounds"]:
                    for interface in profile["interfaces"]:
                        if interface["type"] == "direct" and outbound == {
                            "type": "direct", "tag": interface["id"], "bind_interface": interface["bind_interface"],
                        }:
                            outbound["domain_resolver"] = UNDERLAY_DNS["tag"]
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


def stage_list_routes(stage: Path, profile: dict, snapshot: dict, backend: dict) -> None:
    """Compile current list bindings and write a complete generation, omitting empty sing-box rule tables."""
    groups = profile["groups"]
    rules = domain_routes(profile["lists"], {g["id"]: i for i, g in enumerate(groups)})
    replace_domain_routes(backend, groups[0]["id"], rules)
    snapshot["lists"] = profile["lists"]
    stage_generation(stage, profile, snapshot, backend)


def stage_domain_list(base: Path, stage: Path, list_id: str, values: dict) -> None:
    """Stage all editable list fields under the caller's installation lock while preserving the stable routing ID."""
    identifier(list_id)
    fields(values, "name group masks")
    group_name(values["name"])
    profile, snapshot, backend = managed_profile(base)
    lists = profile["lists"]
    item = {"id": list_id, **values}
    require(all(entry["id"] == list_id or entry.get("name", entry["id"]) != values["name"] for entry in lists), "duplicate list name")
    index = next((i for i, entry in enumerate(lists) if entry["id"] == list_id), None)
    if index is None:
        lists.append(item)
    else:
        lists[index] = item
    stage_list_routes(stage, profile, snapshot, backend)


def stage_delete_list(base: Path, stage: Path, list_id: str) -> None:
    """Remove the named list under the caller's write lock and recompile routes from the remaining lists."""
    identifier(list_id)
    profile, snapshot, backend = managed_profile(base)
    lists = profile["lists"]
    remaining = [entry for entry in lists if entry["id"] != list_id]
    require(len(remaining) == len(lists) - 1, "unknown or duplicate list")
    profile["lists"] = remaining
    stage_list_routes(stage, profile, snapshot, backend)


def stage_binding(base: Path, stage: Path, list_id: str, group_id: str) -> None:
    """Stage a list binding under the installer lock without reimporting secret VPN assets."""
    profile, snapshot, backend = managed_profile(base)
    rank = {group["id"]: i for i, group in enumerate(profile["groups"])}
    require(group_id == "" or group_id in rank, "unknown group")
    lists = profile["lists"]
    item = next((entry for entry in lists if entry["id"] == list_id), None)
    require(item is not None, "unknown list")
    item["group"] = group_id
    stage_list_routes(stage, profile, snapshot, backend)


def stage_create_group(base: Path, stage: Path, group_id: str, name: str = "") -> None:
    """Append an empty deny-only group without changing active routes or reopening original VPN assets."""
    identifier(group_id)
    profile, snapshot, backend = managed_profile(base)
    groups = profile["groups"]
    require(
        group_id != "deny"
        and all(group_id != group["id"] and group_id not in group["exits"] for group in groups),
        "group tag is in use",
    )
    outbounds = backend["outbounds"]
    last_group = groups[-1]["id"]
    positions = [
        i for i, item in enumerate(outbounds)
        if item.get("type") == "selector" and item.get("tag") == last_group
    ]
    require(len(positions) == 1, "last group selector missing or duplicated")
    group = {"id": group_id, "exits": []}
    if name:
        group["name"] = group_name(name)
    snapshot["groups"].append(group.copy())
    unique_group_names(snapshot["groups"])
    if "inbounds" in profile:
        group["defaultExit"] = "deny"
    groups.append(group)
    outbounds.insert(positions[0] + 1, selector(group, "deny"))
    stage_generation(stage, profile, snapshot, backend)


def stage_rename_group(base: Path, stage: Path, group_id: str, name: str) -> None:
    """Replace only the visible name in the source profile and snapshot, retaining all routing and connector data."""
    identifier(group_id)
    group_name(name)
    profile, snapshot, backend = managed_profile(base)
    group = next((item for item in profile["groups"] if item["id"] == group_id), None)
    require(group is not None, "unknown group")
    group["name"] = name
    snapshot["groups"] = [snapshot_group(item) for item in profile["groups"]]
    unique_group_names(snapshot["groups"])
    stage_generation(stage, profile, snapshot, backend)


def stage_delete_group(base: Path, stage: Path, group_id: str) -> None:
    """Remove an empty non-default group and its selector, preserving its domain lists and masks as unbound."""
    identifier(group_id)
    profile, snapshot, backend = managed_profile(base)
    groups = profile["groups"]
    group = next((item for item in groups if item["id"] == group_id), None)
    require(group is not None, "unknown group")
    require(groups[0]["id"] != group_id, "cannot delete default group")
    require(not group["exits"], "group still has exits")
    outbound = selector(group, "deny")
    require(backend["outbounds"].count(outbound) == 1, "group selector differs from profile")
    backend["outbounds"].remove(outbound)
    groups.remove(group)
    for item in profile["lists"]:
        if item["group"] == group_id:
            item["group"] = ""
    snapshot["lists"] = profile["lists"]
    rules = domain_routes(profile["lists"], {item["id"]: i for i, item in enumerate(groups)})
    replace_domain_routes(backend, groups[0]["id"], rules)
    snapshot["groups"] = [snapshot_group(item) for item in groups]
    stage_generation(stage, profile, snapshot, backend)


def synchronize_connector_assignments(profile: dict, groups: list[dict], stage: Path) -> None:
    """Mirror each connector's actual group and one-based priority in the staged source and private metadata."""
    positions = {
        exit_id: (group["id"], priority)
        for group in groups for priority, exit_id in enumerate(group["exits"], 1)
    }
    for connector in profile.get("connectors", []):
        require(connector["id"] in positions, "connector order is incomplete")
        group, priority = positions[connector["id"]]
        connector.update(group=group, priority=priority)
        path = stage / "awg" / connector["id"] / "metadata.json"
        metadata = awg_metadata(stage, connector["id"])
        metadata.update(group=group, priority=priority)
        replace_private(path, json.dumps(metadata, separators=(",", ":")).encode())
    connector_outbounds(profile.get("connectors", []), stage)


def stage_move_exit(base: Path, stage: Path, exit_id: str, expected_group: str, target_group: str, priority: int) -> None:
    """Move an exit to the requested one-based group priority without reopening original VPN assets."""
    connection_id(exit_id)
    identifier(expected_group)
    identifier(target_group)
    profile, snapshot, backend = managed_profile(base)
    groups = profile["groups"]
    by_id = {group["id"]: group for group in groups}
    require(expected_group in by_id and target_group in by_id, "unknown group")
    source, target = by_id[expected_group], by_id[target_group]
    require(exit_id in source["exits"], "exit group changed")
    affected = [source] if source is target else [source, target]
    old_selectors = [selector(group, group.get("defaultExit", "deny")) for group in affected]
    outbounds = backend["outbounds"]
    require(all(outbounds.count(item) == 1 for item in old_selectors), "group selector differs from profile")
    source["exits"].remove(exit_id)
    require(1 <= priority <= len(target["exits"]) + 1, "invalid target priority")
    target["exits"].insert(priority - 1, exit_id)
    if source is not target:
        if "defaultExit" in source and source["defaultExit"] == exit_id:
            source["defaultExit"] = next(iter(source["exits"]), "deny")
        if "defaultExit" in target and len(target["exits"]) == 1:
            target["defaultExit"] = exit_id
    for old_selector, group in zip(old_selectors, affected):
        outbounds[outbounds.index(old_selector)] = selector(group, group.get("defaultExit", "deny"))
    synchronize_connector_assignments(profile, groups, stage)
    snapshot["groups"] = [snapshot_group(group) for group in groups]
    stage_generation(stage, profile, snapshot, backend)


def stage_order(base: Path, stage: Path, groups: list[dict]) -> None:
    """Apply complete group and exit placement to selector order, tie-breaking rules and the default route."""
    profile, snapshot, backend = managed_profile(base)
    old = profile["groups"]
    members = {group["id"] for group in old}
    exits = {exit_id for group in old for exit_id in group["exits"]}
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
        members.remove(group_id)
        for exit_id in group["exits"]:
            require(connection_id(exit_id) in exits, "unknown or repeated exit")
            exits.remove(exit_id)
    require(not exits, "missing exit")
    desired_groups = []
    for group in groups:
        previous = next(item for item in old if item["id"] == group["id"])
        default = previous.get("defaultExit", "deny")
        if (default != "deny" and default not in group["exits"]) or not previous["exits"]:
            default = group["exits"][0] if "inbounds" in profile and group["exits"] else "deny"
        desired = dict(previous, exits=group["exits"])
        if "inbounds" in profile:
            desired["defaultExit"] = default
        desired_groups.append(desired)
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
    if UNDERLAY_DNS in backend.get("dns", {}).get("servers", []):
        for outbound in direct_routes:
            outbound["domain_resolver"] = UNDERLAY_DNS["tag"]
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
    synchronize_connector_assignments(profile, desired_groups, stage)
    ordered_routes = domain_routes(
        profile["lists"], {group["id"]: i for i, group in enumerate(groups)}
    )
    replace_domain_routes(backend, desired_groups[0]["id"], ordered_routes)
    profile["groups"] = desired_groups
    snapshot["groups"] = [snapshot_group(group) for group in desired_groups]
    stage_generation(stage, profile, snapshot, backend)


def main() -> None:
    """Write both validated configurations to new files inside the private staging directory."""
    if len(sys.argv) == 4 and sys.argv[1] in {"--quality-paths", "--dns-paths"}:
        with Path(sys.argv[2]).open("rb") as stream:
            source = os.fstat(stream.fileno()) if sys.argv[1] == "--dns-paths" else None
            export_paths(json.load(stream), Path(sys.argv[3]), source)
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--compare-backend":
        compare_backend_files(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--stage-awg-backend":
        base, stage = Path(sys.argv[2]), Path(sys.argv[3])
        _, _, backend = managed_profile(base)
        if backend != read_verified(base, "sing-box.json", "profile-backend.sha256"):
            raw = json.dumps(backend, indent=2).encode()
            write_private(stage / "sing-box.json", raw)
            write_private(stage / "profile-backend.sha256", (hashlib.sha256(raw).hexdigest() + "\n").encode())
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--awg-start-plan":
        profile, _, _ = managed_profile(Path(sys.argv[2]))
        for connector in profile.get("connectors", []):
            if connector["status"] == "ready":
                mode = "manual" if connector.get("underlays") else "auto"
                plan = [connection_id(connector["id"]), connector_slot(connector), mode]
                if mode == "manual":
                    plan.append(len(connector["underlays"]))
                print(*plan)
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--ready-awg":
        profile, _, _ = managed_profile(Path(sys.argv[2]))
        for connector in profile.get("connectors", []):
            if connector["status"] == "ready":
                print(connection_id(connector["id"]))
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--validate-managed":
        managed_profile(Path(sys.argv[2]))
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--save-list":
        stage = Path(sys.argv[3])
        values = json.loads((stage / "list-values.json").read_bytes(), object_pairs_hook=unique)
        stage_domain_list(Path(sys.argv[2]), stage, sys.argv[4], values)
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--delete-list":
        stage_delete_list(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return
    if len(sys.argv) == 6 and sys.argv[1] == "--rebind":
        stage_binding(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
        return
    if len(sys.argv) in (5, 6) and sys.argv[1] == "--create-group":
        stage_create_group(Path(sys.argv[2]), Path(sys.argv[3]), *sys.argv[4:])
        return
    if len(sys.argv) == 6 and sys.argv[1] == "--rename-group":
        stage_rename_group(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--delete-group":
        stage_delete_group(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return
    if len(sys.argv) == 8 and sys.argv[1] == "--move-exit":
        stage_move_exit(Path(sys.argv[2]), Path(sys.argv[3]), *sys.argv[4:7], int(sys.argv[7]))
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
