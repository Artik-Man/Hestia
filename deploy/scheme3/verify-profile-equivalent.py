"""Check that a compiled scheme3 profile preserves the running routing behavior."""

import json
import sys
from pathlib import Path


def read_json(path: Path) -> object:
    """Read one existing or candidate JSON file, rejecting unreadable or malformed input."""
    return json.loads(path.read_text(encoding="utf-8"))


def tagged_outbounds(config: dict) -> dict:
    """Index unique tagged outbounds while preserving every outbound's nested semantics."""
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ValueError("backend has no outbounds array")
    indexed = {}
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise ValueError("backend contains an invalid outbound")
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not tag or tag in indexed:
            raise ValueError("backend outbound tags are missing or duplicated")
        indexed[tag] = outbound
    return indexed


def backend_equal(current: dict, candidate: dict) -> bool:
    """Compare backend behavior, ignoring only the order of distinct top-level outbounds."""
    if set(current) != set(candidate) or "outbounds" not in current:
        return False
    for name in current:
        if name == "outbounds":
            continue
        if current[name] != candidate[name]:
            return False
    return tagged_outbounds(current) == tagged_outbounds(candidate)


def main() -> None:
    """Exit successfully only when the candidate snapshot/backend match the installed behavior."""
    if len(sys.argv) != 5:
        raise ValueError("expected current snapshot/backend and candidate snapshot/backend")
    current_snapshot, current_backend, candidate_snapshot, candidate_backend = map(
        Path, sys.argv[1:]
    )
    if read_json(current_snapshot) != read_json(candidate_snapshot):
        raise ValueError("candidate snapshot changes the existing controller state")
    current = read_json(current_backend)
    candidate = read_json(candidate_backend)
    if not isinstance(current, dict) or not isinstance(candidate, dict):
        raise ValueError("backend root must be an object")
    if not backend_equal(current, candidate):
        raise ValueError("candidate backend changes existing traffic behavior")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        sys.exit(f"scheme3 adoption check failed: {error}")
