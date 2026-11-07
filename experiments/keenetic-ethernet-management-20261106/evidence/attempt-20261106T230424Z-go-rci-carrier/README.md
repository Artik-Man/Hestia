# Go RCI carrier verification — sandbox blocked

## Question and scope

Verify the shared Go RCI client against the previously authorized read-only `GET /rci/show/interface` on KN-1012. This attempt stopped during SSH preflight before reaching the router; the RCI command was not executed.

## Preconditions and source

- Expected SSH host key: `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`.
- Expected `/bin/ndmc` SHA-256: `6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e`.
- `ssh-keygen -F '[192.168.1.1]:222' -f /Users/artikman/.ssh/known_hosts | ssh-keygen -lf -` returned the expected fingerprint.
- Go version: `go1.27.3 darwin/arm64`.
- Source snapshots and SHA-256 values are in `source/` and `source-sha256.txt`.
- The local token was not read; no request or SSH tunnel was started.

## Attempt

The strict-host-key SSH command to read `sha256sum /bin/ndmc` exited `255` with `ssh: connect to host 192.168.1.1 port 222: Operation not permitted`. This is a local sandbox denial, not a router response. No device-side command was confirmed to have run and no state was changed. The observed output is preserved in `result.json`.
