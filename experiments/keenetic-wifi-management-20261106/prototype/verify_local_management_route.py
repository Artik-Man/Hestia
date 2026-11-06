"""Classify this Mac's route to the Keenetic without saving adapter names or addresses."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[3]
HELPER = (
    REPOSITORY
    / "experiments/keenetic-virtual-management-20261106/evidence/preflight-source-04/profile-readonly-preflight.py"
)
HELPER_SHA256 = "7c0039757a5df800bd7cb2c5de9d6310bbdc204855ce694d0de1430b2e3e49b8"
EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


def main() -> int:
    """Verify the read-only classifier source, run its local route check, and save booleans only."""
    helper_bytes = HELPER.read_bytes()
    helper_digest = hashlib.sha256(helper_bytes).hexdigest()
    if helper_digest != HELPER_SHA256:
        print(json.dumps({"helper_source_matches": False}))
        return 2

    spec = importlib.util.spec_from_file_location("virtual_route_classifier", HELPER)
    if spec is None or spec.loader is None:
        print(json.dumps({"helper_loadable": False, "helper_source_matches": True}))
        return 3
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.collect_local_route()
    record = {
        "observed_utc": datetime.now(UTC).isoformat(),
        "source": "experiments/keenetic-virtual-management-20261106/evidence/preflight-source-04/profile-readonly-preflight.py",
        "source_sha256": helper_digest,
        "source_snapshot_verified": True,
        "route_check": {
            "local_management_route_lookup": result.get(
                "local_management_route_lookup"
            ),
            "wired_management": result.get("wired_management"),
        },
        "raw_route_and_hardware_inventory_persisted": False,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = EVIDENCE / f"attempt-{stamp}-local-management-route.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        json.dumps({"evidence": str(path), **record["route_check"]}, ensure_ascii=False)
    )
    return 0 if result.get("local_management_route_lookup") == "found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
