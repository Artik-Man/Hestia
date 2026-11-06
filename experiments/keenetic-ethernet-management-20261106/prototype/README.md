# Read-only inventory helper

`inventory.py` is a one-off, bounded local runner for the approved read-only command `/bin/ndmc -c 'show interface'`. It first verifies the port-222 SSH host key against the pinned `known_hosts` fingerprint and hashes `/bin/ndmc`; it sends no interface query if either check fails. Each attempt has a 30-second timeout and gets a new timestamped evidence directory.

The helper captures command stdout in memory, writes only its byte count, SHA-256 and a structural allowlist projection, and never persists raw stdout or stderr. The projection keeps per-interface blocks, approved IDs/indexes, exact user-approved profile/port labels, small state/type/speed/duplex enums and booleans indicating exact matches to the user-provided SSIDs `iPhone` and `White Paper`. It discards all other scalar values, including addresses, MACs, secrets, counters and arbitrary descriptions. Review the exact per-attempt runner snapshot and `result-sanitized.json` together.

This helper does not write device state. It does not include any control command and does not assign LAN/WAN roles or change a port mode.
