# Keenetic RCI client

Use the shared authenticated RCI clients for research and the typed Go Ethernet connector. Contract and acceptance: [feature specification](../../docs/features/keenetic-rci-client.md).

## Go experiments

Place experiment commands under `backend/cmd/` and import the shared `github.com/Artik-Man/Hestia/pkg/keeneticrci` package. For physical Ethernet inventory, run the existing command from `backend/`:

```sh
go run ./cmd/keenetic-rci-ethernet \
  -base-url http://127.0.0.1:79 \
  -token-file "$HOME/.config/hestia/keenetic-rci-token"
```

The base URL is the HTTP endpoint visible to the experiment. For a remote KN-1012, create a temporary, host-key-pinned SSH forward to router loopback port 79, then use the local forwarded address. Keep SSH setup/cleanup in the experiment harness. The client reads the token file on each request, sends `X-NDMA-TKN`, disables proxies and redirects, bounds the response, and parses JSON. It never prints credentials or raw body data.

Define each operation with an explicit `RciOperation`. GET is the default and cannot carry a body. POST requires `changes_state=True` and a client configured with `allow_writes=True`. Enabling writes does not authorize a device mutation by itself; the exact operation still needs Product Owner permission and an experiment protocol.

## Go connector

Create `FileTokenSource{Path: ...}`, pass it and a fixed loopback or HTTPS endpoint to `NewClient(Config{...})`, then construct `NewEthernetConnector(client)` and call `List(ctx)`. `List` issues only `GET /rci/show/interface` and returns sorted, deduplicated `EthernetPort` values. Optional speed/duplex are nil when Keenetic omits them; `LinkDown` is only the current absence of active link.

Do not pass token values through arguments, logs, environment dumps, or evidence. Do not log generic JSON bodies. Save only operation metadata and fields needed by the experiment; discard unrelated addresses, MACs, DHCP, Wi-Fi, VPN, and configuration data. A timeout, auth error, unsupported schema, unknown link state, or conflicting duplicate must stop the operation without fallback to another endpoint or protocol.
