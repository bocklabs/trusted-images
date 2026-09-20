"""Emit recovery promotion context from the original inventory."""

import json
import sys
import yaml

spec = yaml.safe_load(open(sys.argv[1]))["spec"]
validation = spec["validation"]
app = sys.argv[2]
recover_tag = sys.argv[3]
if spec["destination"]["package"] != f"ghcr.io/bocklabs/{app}":
    raise SystemExit("FATAL: recovered inventory destination does not match app")
if recover_tag and not recover_tag.startswith(spec["upstream"]["tag"] + "-bocklabs."):
    raise SystemExit("FATAL: recover_tag does not match the original upstream tag")
print(f"upstream_ref={spec['upstream']['ref']}")
print(f"upstream_tag={spec['upstream']['tag']}")
print(f"upstream_digest={spec['upstream']['digest']}")
print(f"dest_package={spec['destination']['package']}")
print(f"patch_policy={spec['patchPolicy']}")
print(f"app={app}")
print(f"validation_type={validation['type']}")
PARAM_OUTPUTS = {
    "port": "validation_port",
    "path": "validation_path",
    "expectStatus": "validation_expect_status",
    "durationSeconds": "validation_duration_seconds",
    "timeoutSeconds": "validation_timeout_seconds",
    "expectedExit": "validation_expected_exit",
}
for key, output in PARAM_OUTPUTS.items():
    if key in validation:
        print(f"{output}={validation[key]}")
if "command" in validation:
    print("validation_command=" + json.dumps(validation["command"]))
if "expectedPlatforms" in validation:
    print("validation_expected_platforms=" + ",".join(validation["expectedPlatforms"]))
if validation.get("env"):
    print("validation_env=" + json.dumps(validation["env"]))
