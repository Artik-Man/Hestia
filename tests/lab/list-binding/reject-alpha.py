"""Fail the test backend start for a candidate routing bound.lab.test via group-alpha."""

import json
import os
from pathlib import Path

config = json.loads(
    (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "sing-box.json").read_text()
)
for rule in config["route"]["rules"]:
    if (
        rule.get("domain_suffix") == "bound.lab.test"
        and rule["outbound"] == "group-alpha"
    ):
        raise SystemExit("QA: refused candidate routing bound.lab.test via group-alpha")
