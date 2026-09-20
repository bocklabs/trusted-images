"""Validate the published candidate decision identity."""

import importlib.util
import json
import os

spec = importlib.util.spec_from_file_location("evaluate_promotion", "scripts/evaluate_promotion.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
decision = json.load(open("candidate-decision.json"))
module.validate_decision(decision)
if decision["app"] != os.environ["APP"] or decision["published"]["digest"] != decision["candidate"]["digest"]:
    raise SystemExit("FATAL: published decision identity is invalid")
