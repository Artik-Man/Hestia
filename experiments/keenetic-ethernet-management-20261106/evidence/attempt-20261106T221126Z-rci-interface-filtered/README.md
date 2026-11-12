# Filtered RCI Ethernet inventory read

## Question and scope

Repeat the successful read-only `GET /rci/show/interface` with a stricter in-memory filter. Include only physical-port records whose `id` matches `GigabitEthernetN/M` and whose `type` is `Port`; deduplicate by ID. Return only `id`, `type`, `link`, `state`, `speed`, and `duplex`. Do not emit general schema member names, IP/MAC/DHCP values, Wi-Fi/VPN names, descriptions, or the raw response.

## Preconditions and transport

- KN-1012, expected KeeneticOS release `5.02.B.3.0-2` / `5.2 Beta 3`.
- SSH host-key fingerprint: `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`.
- Expected `/bin/ndmc` SHA-256: `6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e`; helper checks via the confirmed `sha256sum /bin/ndmc` command.
- Token is read from `/Users/artikman/.config/hestia/keenetic-rci-token` only in memory. The helper sends it as `X-NDMA-TKN`; it is not printed or saved.
- Temporary SSH forward binds only `127.0.0.1` to router loopback port 79 and closes in `finally`.

## Exact source and invocation

- Helper: `prototype/rci_read_ethernet.py`.
- Immutable source snapshot: `source/rci_read_ethernet.py`.
- SHA-256 of both before execution: `cdfd63b789c676370eccb1141e68f86583e411ed31640d605236583b2fa81249`.
- Command: `python3 experiments/keenetic-ethernet-management-20261106/prototype/rci_read_ethernet.py`.

## Expected result

HTTP 200 JSON and one row per physical Ethernet port. Compare `GigabitEthernet0/0` with the prior LAN1 controlled-link observation. A link-down result for another port does not prove the jack is unused. This read does not change port role or settings and does not confirm traffic forwarding.

## Result

At `2026-11-06T22:12:02Z`, the request returned HTTP 200 JSON, 34,929 bytes. Host key and `ndmc` hashes matched the pinned values. The strict parser found five unique physical `Port` records; its output is preserved in `result.json`. The raw response and non-Ethernet interface data were not saved. The temporary SSH process was terminated and waited for in the helper's `finally` block. No router configuration or runtime state was changed.
