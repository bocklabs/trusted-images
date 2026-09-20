"""Validate the final merged candidate decision."""

import importlib.util
import json
import os

spec = importlib.util.spec_from_file_location(
    "evaluate_promotion", "scripts/evaluate_promotion.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
decision = json.load(open("candidate-decision.json"))
module.validate_decision(decision)
if (
    decision["app"] != os.environ["APP"]
    or decision["published"]["digest"] != os.environ["CANDIDATE_DIGEST"]
    or decision["provenance"]["merged"] is not True
):
    raise SystemExit("FATAL: final candidate decision merge state is invalid")
