# Go RCI Ethernet inventory and carrier-client verification

## Question and scope

Does the shared Go RCI client authenticate to the already confirmed KN-1012 endpoint and parse the physical Ethernet inventory? The single request was read-only `GET /rci/show/interface`; the Go CLI printed only typed Ethernet fields and response metadata.

## Environment and preflight

- Target: KN-1012, KeeneticOS 5.2 Beta 3, Entware; RCI endpoint forwarded from router loopback `127.0.0.1:79` to local `127.0.0.1:17979`.
- SSH host-key fingerprint matched the existing pin: `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`.
- Read-only `sha256sum /bin/ndmc` matched `6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e`.
- SSH used batch mode, the pinned known_hosts file and `StrictHostKeyChecking=yes`. The SSH tunnel was terminated after the request.
- The owner-only token file was read by the Go client; its contents were not printed or saved. The token file was mode `0600`, owner UID matched the local process.
- Go version: `go1.27.3 darwin/arm64`. The executed CLI binary hash is recorded in `binary-sha256.txt`.
- Exact Go source snapshots and hashes are in `source/` and `source-sha256.txt`.

## Command and result

The Go command was invoked as:

```sh
/private/tmp/keenetic-rci-ethernet \
  -base-url http://127.0.0.1:17979 \
  -token-file /Users/artikman/.config/hestia/keenetic-rci-token
```

It exited `0` at `2026-11-06T23:08:06Z`, returned HTTP `200 application/json`, `34,933` bytes and response SHA-256 `f5549147457d0efd5fe57c0662895d6bb96b2ebfbef58d7918eba387827dca17`. The sanitized response is `result.json`; no raw JSON was saved.

The five physical ports matched the earlier inventory: `GigabitEthernet0/0` down; `/0/1` and `/0/2` up at 100/full; `/0/3` down; `GigabitEthernet1/0` up at 1000/full. No port or router setting was changed.

## Limits

This verifies the Go authentication/client and typed Ethernet response parsing for this endpoint and firmware. It does not prove RCI write operations, mapping RCI port IDs to kernel interface names, REST API integration, watcher behavior on the router, traffic forwarding, or support for another firmware.
