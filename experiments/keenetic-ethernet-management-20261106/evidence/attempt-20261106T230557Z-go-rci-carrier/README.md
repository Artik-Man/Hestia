# Go RCI loopback attempt — sandbox blocked

The strict host-key and remote binary-hash preflight had already succeeded. The tunnel was open, but the default sandbox denied the Go client's connection to its local forwarded endpoint. The CLI exited 1 with `{"error":"transport","result":"failed"}` and no RCI response was received in this invocation. No state was changed. The same bounded GET was retried with the Go client under the approved sandbox escalation in the separate `attempt-20261106T230806Z-go-rci-carrier` record.

The exact observed CLI output was copied from the command result after its initial output file was replaced by the successful retry; it is a transcript copy, not the original file bytes. Source snapshot and SHA-256 remain in `source/` and `source-sha256.txt`.
