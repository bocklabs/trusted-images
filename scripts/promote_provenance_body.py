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
    print(f"- {name}: {', '.join(values) or '-'}")
print()
print("### Package changes")
print()
changes = decision["packages"]["changes"] + decision["packages"]["downgrades"]
for change in changes:
    print(f"- {change['ecosystem']}/{change['name']}: {change['change']} {change['before'] or '-'} → {change['after'] or '-'}")
print()
print("### Warnings")
print()
print(decision["reason"])
print()
catalog = decision["policy"]["kev"]["catalog"]
print("### KEV snapshot")
print()
print(f"- URL: {catalog['url']}")
print(f"- SHA256: `{catalog['sha256']}`")
print(f"- Version: {catalog['catalog_version']}")
print(f"- Released: {catalog['date_released']}")
print(f"- Fetched: {catalog['fetched_at']}")
print(f"- Matches: {', '.join(decision['policy']['kev']['matched']) or '-'}")
print()
print("### Acceptance expiry")
print()
acceptance = decision["policy"]["acceptance"]
print(acceptance["expires_at"] if acceptance else "N/A — no KEV exception")
