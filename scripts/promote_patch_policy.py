"""Emit the patch policy from an inventory image."""

import json
import sys
import yaml
spec = yaml.safe_load(open(sys.argv[1]))["spec"]
policy = {"patchPolicy": spec["patchPolicy"]}
if spec["patchPolicy"] == "disabled":
    policy["patchDisabledReason"] = spec["patchDisabledReason"]
print(json.dumps(policy, sort_keys=True))
