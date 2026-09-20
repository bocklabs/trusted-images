"""Evaluate and export one promotion decision."""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

policy = json.loads(Path("validation-context/patch-policy.json").read_text())
args = [
    sys.executable, "scripts/evaluate_promotion.py",
    "--app", os.environ["APP"],
    "--source-sha", os.environ["SOURCE_SHA"],
    "--run-id", os.environ["RUN_ID"],
    "--run-attempt", os.environ["RUN_ATTEMPT"],
    "--proposed-tag", os.environ["INTERNAL_TAG"],
    "--index", "upstream-index.json",
    "--upstream-index-digest", os.environ["UPSTREAM_INDEX_DIGEST"],
    "--child-manifest", "child-manifest.json",
    "--child-config", "child-config.json",
    "--full-report", "trivy-before-full.json",
    "--fixable-report", "trivy-copa.json",
    "--kev", "kev.json",
    "--kev-fetched-at", Path("kev-fetched-at.txt").read_text().strip(),
    "--now", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "--validation-result", json.loads(Path("validation-evidence.json").read_text())["validation"]["result"],
    "--patch-policy", policy["patchPolicy"],
    "--out", "candidate-decision.json",
]
if policy["patchPolicy"] == "disabled":
    reason = policy["patchDisabledReason"]
    args += ["--patch-disabled-class", reason["class"], "--patch-disabled-detail", reason["detail"]]
if Path("trivy-after-full.json").is_file():
    original = json.loads(Path("original-candidate-decision.json").read_text()) if Path("original-candidate-decision.json").is_file() else None
    classification = original["copa"]["classification"] if original else "succeeded"
    args += [
        "--after-full-report", "trivy-after-full.json",
        "--scan-receipt", "scan-receipt.json",
        "--candidate-digest", os.environ["CANDIDATE_DIGEST"],
        "--copa-classification", classification,
    ]
if Path("acceptance.json").is_file() and Path("github-evidence.json").is_file():
    args += [
        "--acceptance", "acceptance.json",
        "--github-evidence", "github-evidence.json",
        "--github-repository", os.environ["GITHUB_REPOSITORY"],
    ]
if os.environ.get("RESUME_ORIGINAL_RUN_ID"):
    args += [
        "--resume-original-run-id", os.environ["RESUME_ORIGINAL_RUN_ID"],
        "--resume-original-run-attempt", os.environ["RESUME_ORIGINAL_RUN_ATTEMPT"],
        "--resume-original-source-sha", os.environ["RESUME_ORIGINAL_SOURCE_SHA"],
        "--resume-artifact-id", os.environ["RESUME_ARTIFACT_ID"],
    ]
result = subprocess.run(args)
if result.returncode:
    print("Candidate retained for operator review; publisher will not run.")
if Path("candidate-decision.json").is_file():
    decision = json.loads(Path("candidate-decision.json").read_text())
    decision["supersedes"] = {
        "higher_upstream": os.environ.get("HIGHER_UPSTREAM") == "true",
        "original_child_selected": os.environ.get("ORIGINAL_CHILD_SELECTED") == "true",
    }
    Path("candidate-decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    eligible = decision["eligible"]
    with Path(os.environ.get("GITHUB_OUTPUT", "/dev/null")).open("a") as output:
        output.write(f"eligible={str(eligible).lower()}\n")
raise SystemExit(result.returncode)
