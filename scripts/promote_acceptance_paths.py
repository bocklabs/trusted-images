"""Resolve the KEV acceptance path and matched CVEs."""

import importlib.util
import hashlib
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "evaluate_promotion", "scripts/evaluate_promotion.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
report = module.findings(
    json.loads(Path("trivy-full.json").read_text()), "final report"
)
feed = json.loads(Path("kev.json").read_text())
matched = sorted(
    {key.split("|", 2)[2] for key in report}
    & {row["cveID"] for row in feed["vulnerabilities"]}
)
digest = (
    "sha256:" + hashlib.sha256(Path("candidate-manifest.json").read_bytes()).hexdigest()
)
Path("acceptance-path.txt").write_text(
    module.acceptance_path(__import__("os").environ["APP"], digest, matched) + "\n"
)
Path("acceptance-matched.txt").write_text(
    "\n".join(matched) + ("\n" if matched else "")
)
