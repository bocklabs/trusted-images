"""Verify recovery inventory bindings for the original report."""

import json
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as stream:
    spec = yaml.safe_load(stream)["spec"]
with open(sys.argv[2], encoding="utf-8") as stream:
    manifest = json.load(stream)
expected = {
    "app": sys.argv[3],
    "upstream_ref": spec["upstream"]["ref"],
    "upstream_tag": spec["upstream"]["tag"],
}
if manifest != expected:
    raise SystemExit(
        "FATAL: original report artifact is not bound to the recovered inventory"
    )
