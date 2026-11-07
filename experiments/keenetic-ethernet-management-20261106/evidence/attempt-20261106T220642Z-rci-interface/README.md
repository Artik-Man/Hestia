# RCI Ethernet interface read attempt

## Question and scope

Can the KN-1012 local RCI return the interface inventory as JSON when authenticated with the owner's local access token? The single operation is `GET /rci/show/interface`; no settings or state are changed. The helper discards the raw body and emits only Ethernet-like identities/state fields, JSON shape metadata, response size, and a digest. IP addresses, MAC addresses, DHCP details, Wi-Fi data, and all other fields are not saved.

## Environment and preconditions

- Target: Keenetic Giga KN-1012, expected release `5.02.B.3.0-2` / KeeneticOS `5.2 Beta 3`.
- SSH endpoint: `root@192.168.1.1:222`; host key must match `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo` in the pinned known_hosts file.
- Before opening the tunnel, verify `/bin/ndmc` SHA-256 equals `6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e`.
- Access token is read at runtime from `/Users/artikman/.config/hestia/keenetic-rci-token`; its value is never printed or saved. Expected file mode was observed as `0600`.
- Transport is a temporary local-only SSH forward to router loopback port 79. No `hestia-prod` VM is accessed; no router process, file, setting, or persistent listener is created.

## Exact prepared source

- Helper: `prototype/rci_read_ethernet.py`.
- Immutable attempt snapshot: `source/rci_read_ethernet.py`.
- SHA-256 of both files before execution: `f1c991f8f23fa922f7d7ac98b45af15041a9e004da2e66bd7be1e007d3d6ab78`.
- Invocation: `python3 experiments/keenetic-ethernet-management-20261106/prototype/rci_read_ethernet.py`.

## Expected result and acceptance boundary

HTTP 200 with JSON. If the schema exposes physical Ethernet interfaces, emit only identifier/name and type/link/status fields. A successful endpoint response alone does not establish the complete interface contract or the physical-port mapping; compare the Ethernet identity and link fields only with the already recorded controlled LAN1 observation (`GigabitEthernet0/0`, link down → up → down). On non-200, malformed JSON, tunnel failure, hash mismatch, or unsupported schema, preserve only sanitized status/error metadata and stop. Do not try another endpoint, auth flow, CLI query, or mutation in this attempt.

## Result

The first execution exited `1` during `verify_remote_binary`; it did not load the token or open the SSH tunnel, so the RCI GET was not sent. A sanitized diagnostic repeated the same read-only preflight and returned exit `127`, no expected digest, and a 30-byte stderr that was intentionally not retained. The helper had invoked `/bin/sha256sum`, while prior evidence shows the available command is `sha256sum`; this attempt therefore stopped at the precondition. See `result.json`. No router state changed. The corrected helper is preserved as a new source revision and will be run under a separate attempt record.
