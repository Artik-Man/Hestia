"""Check the public quality API against the live selector while injecting a path-specific UDP fault."""
import json
import time
from pathlib import Path
from urllib.request import urlopen


def read(url: str) -> dict:
    """Read a JSON response from a loopback HTTP service in the test network namespace."""
    with urlopen("http://127.0.0.1:" + url, timeout=2) as response:
        return json.load(response)


def wait_for(active: str, degraded: bool) -> None:
    """Wait for matching probe scores, public ranking, available reserve, and confirmed sing-box choice."""
    end = time.monotonic() + 25
    last = {}
    while time.monotonic() < end:
        report = read("8080/api/quality")
        group, empty = report["groups"]
        rows = group["connections"]
        last = {row["id"]: row["result"] for row in rows}
        if all(last[key]["overall"] is not None for key in ("one", "two")):
            if (rows[0]["id"] == active and rows[0]["active"] and last["two"]["overall"] == 100
                    and not rows[1]["active"] and empty["connections"] == []
                    and (last["one"]["overall"] < 100) == degraded
                    and read("9090/proxies/finland")["now"] == active):
                print(json.dumps({"active": active, "rows": rows}, ensure_ascii=False), flush=True)
                return
        time.sleep(.25)
    raise ValueError(f"missing confirmed {active} selection: {last}")


if __name__ == "__main__":
    wait_for("one", False)
    Path("one/drop-udp").touch()
    wait_for("two", True)
