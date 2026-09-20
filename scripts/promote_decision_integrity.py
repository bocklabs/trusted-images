"""Validate candidate decision binding and acceptance evidence."""

import datetime
import importlib.util
import json
import os
import sys
from types import SimpleNamespace

path = sys.argv[1]
decision = json.load(open(path))
spec = importlib.util.spec_from_file_location("evaluate_promotion", "scripts/evaluate_promotion.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.validate_decision(decision)
expected = {
    "app": os.environ["APP"],
    "source_sha": os.environ["SOURCE_SHA"],
    "run_id": os.environ["RUN_ID"],
    "upstream_index_digest": os.environ["UPSTREAM_INDEX_DIGEST"],
}
mismatches = [f"{key}={decision.get(key)!r}" for key, value in expected.items() if decision.get(key) != value]
if decision.get("run_attempt") != int(os.environ["RUN_ATTEMPT"]):
    mismatches.append(f"run_attempt={decision.get('run_attempt')!r}")
if not decision.get("eligible") or decision.get("validation", {}).get("result") != "pass":
    mismatches.append(f"eligible={decision.get('eligible')!r}")
accepted_run = os.environ.get("ACCEPTED_CANDIDATE_RUN_ID", "")
if accepted_run:
    expected_resume = {
        "original_run_id": accepted_run,
        "original_run_attempt": int(os.environ["RESUME_ORIGINAL_RUN_ATTEMPT"]),
        "original_source_sha": os.environ["RESUME_ORIGINAL_SOURCE_SHA"],
        "artifact_id": int(os.environ["RESUME_ARTIFACT_ID"]),
    }
    if decision.get("resume") != expected_resume:
        mismatches.append(f"resume={decision.get('resume')!r}")
    original = json.load(open("candidate-artifact/original-candidate-decision.json"))
    module.validate_decision(original)
    if original.get("run_id") != accepted_run or original.get("eligible") is not False or original.get("reason") != "missing_kev_acceptance":
        mismatches.append("original_decision")
    api_run = json.load(open("publisher-resume-run.json"))
    api_artifact = json.load(open("publisher-resume-artifact.json"))
    if (
        api_run.get("id") != int(accepted_run)
        or api_run.get("repository", {}).get("full_name") != os.environ["REPO"]
        or api_run.get("path") != ".github/workflows/promote.yaml"
        or api_run.get("event") != "workflow_dispatch"
        or api_run.get("head_branch") != "main"
        or api_run.get("head_sha") != os.environ["RESUME_ORIGINAL_SOURCE_SHA"]
        or api_run.get("run_attempt") != expected_resume["original_run_attempt"]
        or api_run.get("status") != "completed"
    ):
        mismatches.append("resume_run_api")
    if (
        api_artifact.get("id") != expected_resume["artifact_id"]
        or api_artifact.get("name") != "candidate"
        or api_artifact.get("expired") is not False
        or api_artifact.get("workflow_run", {}).get("id") != int(accepted_run)
    ):
        mismatches.append("resume_artifact_api")
elif decision.get("resume") is not None:
    mismatches.append("resume")
if decision.get("policy", {}).get("acceptance") is not None:
    proof_args = SimpleNamespace(
        acceptance="candidate-artifact/acceptance.json",
        github_evidence="candidate-artifact/github-evidence.json",
        github_repository=os.environ["REPO"],
        app=os.environ["APP"],
    )
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    acceptance = module.acceptance_evidence(
        proof_args, decision["candidate"]["digest"], decision["policy"]["kev"]["matched"], now
    )
    if acceptance != decision["policy"]["acceptance"]:
        mismatches.append("acceptance")
if mismatches:
    raise SystemExit("FATAL: candidate decision binding failed: " + ", ".join(mismatches))
