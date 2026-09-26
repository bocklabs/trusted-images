"""Render the provenance pull-request body."""

import json
import sys
from pathlib import Path

run_url, candidate_digest, internal_tag = sys.argv[1:]
decision = json.loads(Path("candidate-decision.json").read_text(encoding="utf-8"))
print("Machine-generated provenance record per docs/pipeline.md.")
print()
print(f"- Run: {run_url}")
print(f"- Candidate digest: `{candidate_digest}`")
print(f"- Internal tag: {internal_tag}")
print()
print("### Before/final CVE evidence")
print()
for name, values in decision["delta"]["cves"].items():
    print(f"- {name}: {len(values)} IDs; sample: {', '.join(values[:20]) or '-'}")
print()
print("### Package changes")
print()
changes = decision["packages"]["changes"] + decision["packages"]["downgrades"]
print(f"Total package changes: {len(changes)}; showing at most 20.")
for change in changes[:20]:
    print(
        f"- {change['ecosystem'][:120]}/{change['name'][:120]}: {change['change']} {(change['before'] or '-')[:120]} → {(change['after'] or '-')[:120]}"
    )
print()
print("### Warnings")
print()
print(decision["reason"][:300])
print("\nPresentation is abbreviated. Complete CVEs, package changes and warnings are in this PR's provenance JSON and the run's candidate-decision/trivy-full-report artifacts.")
print()
catalog = decision["policy"]["kev"]["catalog"]
print("### KEV snapshot")
print()
print(f"- URL: {catalog['url']}")
print(f"- SHA256: `{catalog['sha256']}`")
print(f"- Version: {catalog['catalog_version']}")
print(f"- Released: {catalog['date_released']}")
print(f"- Fetched: {catalog['fetched_at']}")
matches = decision['policy']['kev']['matched']
print(f"- Matches: {len(matches)}; sample: {', '.join(matches[:20]) or '-'}")
print()
print("### Acceptance expiry")
print()
acceptance = decision["policy"]["acceptance"]
print(acceptance["expires_at"] if acceptance else "N/A — no KEV exception")
