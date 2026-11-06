"""In the test guest only, refuse a candidate credential that would make group-alpha default."""

import json
import os
from pathlib import Path

config = json.loads(
    (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "sing-box.json").read_text()
)
if config["route"]["final"] == "group-alpha":
    raise SystemExit("QA: rejected candidate with group-alpha as default")
