"""Emit promotion context and patch policy from the inventory."""

import json
import sys
import yaml

stage, path = sys.argv[1:3]
spec = yaml.safe_load(open(path))["spec"]
if stage == "policy":
    policy = {"patchPolicy": spec["patchPolicy"]}
    if spec["patchPolicy"] == "disabled":
        policy["patchDisabledReason"] = spec["patchDisabledReason"]
    print(json.dumps(policy, sort_keys=True))
    sys.exit(0)
if stage not in {"normal", "recovery"}:
    raise SystemExit("FATAL: unknown inventory stage: " + stage)
app = sys.argv[3]
if spec["destination"]["package"] != f"ghcr.io/bocklabs/{app}":
    context = "recovered inventory" if stage == "recovery" else "validation context"
    raise SystemExit(f"FATAL: {context} destination does not match app")
if stage == "recovery":
    recover_tag = sys.argv[4]
    if recover_tag and not recover_tag.startswith(spec["upstream"]["tag"] + "-bocklabs."):
        raise SystemExit("FATAL: recover_tag does not match the original upstream tag")
print(f"upstream_ref={spec['upstream']['ref']}")
print(f"upstream_tag={spec['upstream']['tag']}")
print(f"upstream_digest={spec['upstream']['digest']}")
print(f"dest_package={spec['destination']['package']}")
print(f"patch_policy={spec['patchPolicy']}")
print(f"app={app}")
if stage == "normal":
    sys.exit(0)
validation = spec["validation"]
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
