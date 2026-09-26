"""Render the promotion run summary."""

from collections import Counter
import json
from pathlib import Path


def rows(path):
    if not Path(path).is_file():
        return []
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    results = report.get("Results")
    if results is None:
        results = []
    elif not isinstance(results, list):
        raise ValueError("Trivy report Results must be an array or null")
    return [
        (
            result.get("Class", "unknown"),
            finding.get("VulnerabilityID", ""),
            finding.get("PkgName", ""),
            finding.get("Severity", ""),
            finding.get("SeveritySource", ""),
        )
        for result in results
        for finding in result.get("Vulnerabilities") or []
    ]


print("### Before/final CVE evidence")
print()
print("| Stage | Class | Severity | Package/CVE entries |")
print("| --- | --- | --- | ---: |")
for stage, source in (
    ("before", "trivy-before-full.json"),
    ("final", "trivy-full.json"),
):
    counts = Counter((row[0], row[3]) for row in set(rows(source)))
    for (kind, severity), count in sorted(counts.items()):
        print(f"| {stage} | {kind} | {severity} | {count} |")
print()
decision_path = Path("candidate-decision.json")
if decision_path.is_file():
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    print("### Package changes")
    print()
    print("| Ecosystem | Package | Change | Before | After |")
    print("| --- | --- | --- | --- | --- |")
    changes = decision["packages"]["changes"] + decision["packages"]["downgrades"]
    for change in sorted(changes, key=lambda value: (value["ecosystem"], value["name"]))[:20]:
        print(
            f"| {change['ecosystem'][:120]} | {change['name'][:120]} | {change['change']} | {(change['before'] or '-')[:120]} | {(change['after'] or '-')[:120]} |"
        )
    print()
    print(f"Total package changes: {len(changes)}; showing at most 20.")
    print()
    print("### Warnings")
    print()
    print(decision["reason"][:300])
    print("Presentation is abbreviated; complete findings, package changes and warnings remain in candidate-decision/trivy-full-report artifacts and provenance JSON.")
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
    acceptance = decision["policy"]["acceptance"]
    print()
    print("### Acceptance expiry")
    print()
    print(acceptance["expires_at"] if acceptance else "N/A — no KEV exception")
    print()
