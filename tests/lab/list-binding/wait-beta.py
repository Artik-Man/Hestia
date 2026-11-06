"""Delay only the beta candidate watcher startup while its unconfirmed data path can be probed."""

import json
import time
from pathlib import Path

lists = json.loads(Path("/etc/hestia/snapshot.json").read_text())["lists"]
if any(item["id"] == "target" and item["group"] == "group-beta" for item in lists):
    time.sleep(16)
