"""Verify recovery inventory bindings for the original report."""

import json
import sys
import yaml

spec = yaml.safe_load(open(sys.argv[1]))["spec"]
manifest = json.load(open(sys.argv[2]))
expected = {
    "app": sys.argv[3],
    "upstream_ref": spec["upstream"]["ref"],
    "upstream_tag": spec["upstream"]["tag"],
}
if manifest != expected:
    raise SystemExit(
        "FATAL: original report artifact is not bound to the recovered inventory"
    )
