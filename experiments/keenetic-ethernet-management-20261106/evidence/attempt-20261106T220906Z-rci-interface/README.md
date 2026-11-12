# RCI Ethernet interface read attempt — corrected preflight

## Question and scope

Can the KN-1012 local RCI return interface inventory JSON using the owner-provided access token? This attempt sends only `GET /rci/show/interface`, authenticated by `X-NDMA-TKN`, over a temporary SSH forward to loopback port 79. It does not perform any write request or alter router configuration.

The helper parses the response in memory, prints only Ethernet-like identity/type/link/status fields and schema key/type metadata, and discards the raw response. Addresses, MAC addresses, DHCP data, Wi-Fi details, and all other interface values are excluded from output and evidence.

## Environment and preconditions

- Target: Keenetic Giga KN-1012, expected release `5.02.B.3.0-2` / KeeneticOS `5.2 Beta 3`.
- SSH endpoint: `root@192.168.1.1:222`; known_hosts fingerprint must equal `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`.
- Before opening the tunnel, verify `sha256sum /bin/ndmc` equals `6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e`.
- Read token at runtime from `/Users/artikman/.config/hestia/keenetic-rci-token`; do not print, save, or place it in the command line.
- The SSH tunnel binds only to `127.0.0.1` and closes on completion. No Hestia VM or non-loopback client traffic is used.

## Exact source and invocation

- Helper: `prototype/rci_read_ethernet.py`.
- Immutable source snapshot: `source/rci_read_ethernet.py`.
- SHA-256 of the helper and snapshot before execution: `c1a70e3bc3c0cae93163276164f799f0924da18725ccf622894a3fb86378caec`.
- Command: `python3 experiments/keenetic-ethernet-management-20261106/prototype/rci_read_ethernet.py`.

## Expected result and limit

HTTP 200 with JSON. A response is evidence only for the fields observed on this firmware. If physical Ethernet interfaces can be identified, compare them only against the existing controlled LAN1 observation (`GigabitEthernet0/0`, link down → up → down); do not infer that any link-down port is unused. If the response is denied or schema is unclear, stop without trying another endpoint, auth flow, CLI query, or configuration mutation.

## Result

The RCI request returned HTTP 200 with JSON, 34,930 bytes; SHA-256 was `f5e0dc8b36024472665d7737245abf9ce1ea3717089ebef84a1a63c69eb52d1c`. Host key and `ndmc` hashes matched their pinned values. The initial output filter found duplicate physical-port records and also exposed non-Ethernet interface names in its schema metadata, so its inventory summary is rejected and is not copied into evidence. The raw response was not saved. A stricter filter now accepts only IDs matching `GigabitEthernetN/M` with type `Port`, deduplicates by ID, and suppresses all schema member names; that source is recorded separately before a bounded repeat of the same GET. No state changed.
