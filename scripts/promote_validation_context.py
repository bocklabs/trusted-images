"""Emit validation context from an inventory image."""

import sys
import yaml

spec = yaml.safe_load(open(sys.argv[1]))["spec"]
app = sys.argv[2]
if spec["destination"]["package"] != f"ghcr.io/bocklabs/{app}":
    raise SystemExit("FATAL: validation context destination does not match app")
print(f"upstream_ref={spec['upstream']['ref']}")
print(f"upstream_tag={spec['upstream']['tag']}")
print(f"upstream_digest={spec['upstream']['digest']}")
print(f"dest_package={spec['destination']['package']}")
print(f"patch_policy={spec['patchPolicy']}")
print(f"app={app}")
