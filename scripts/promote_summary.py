"""Render the promotion run summary."""

import json
from pathlib import Path

def rows(path):
    if not Path(path).is_file():
        return []
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        (finding.get("VulnerabilityID", ""), finding.get("PkgName", ""),
         finding.get("Severity", ""), finding.get("SeveritySource", ""))
        for result in report.get("Results", [])
        for finding in result.get("Vulnerabilities") or []
    ]

print("### Before/final CVE evidence")
print()
print("| Stage | CVE | Package | Severity | Severity source |")
print("| --- | --- | --- | --- | --- |")
for stage, source in (("before", "trivy-before-full.json"), ("final", "trivy-full.json")):
    for cve, package, severity, severity_source in sorted(set(rows(source))):
        print(f"| {stage} | {cve} | {package} | {severity} | {severity_source or '-'} |")
print()
decision_path = Path("candidate-decision.json")
if decision_path.is_file():
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    print("### Package changes")
    print()
    print("| Ecosystem | Package | Change | Before | After |")
    print("| --- | --- | --- | --- | --- |")
    changes = decision["packages"]["changes"] + decision["packages"]["downgrades"]
    for change in sorted(changes, key=lambda value: (value["ecosystem"], value["name"])):
        print(f"| {change['ecosystem']} | {change['name']} | {change['change']} | {change['before'] or '-'} | {change['after'] or '-'} |")
    print()
    fixable = {row[0] for row in rows("trivy-copa.json")}
    print("### Warnings")
    print()
    for cve, package, severity, severity_source in sorted(set(rows("trivy-full.json"))):
        if cve not in fixable:
            print(f"- no-fix: {cve} / {package} / {severity} / {severity_source or '-'}")
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
    acceptance = decision["policy"]["acceptance"]
    print()
    print("### Acceptance expiry")
    print()
    print(acceptance["expires_at"] if acceptance else "N/A — no KEV exception")
    print()
