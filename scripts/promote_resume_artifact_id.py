"""Select the exact preserved candidate artifact id."""

import json
import sys

rows = [
    json.loads(line)
    for line in open("resume-artifacts.jsonl", encoding="utf-8")
    if line.strip()
]
valid = [
    row
    for row in rows
    if row.get("expired") is False
    and row.get("workflow_run", {}).get("id") == int(sys.argv[1])
]
if (
    len(rows) != 1
    or len(valid) != 1
    or not isinstance(valid[0].get("id"), int)
    or valid[0]["id"] <= 0
):
    raise SystemExit("FATAL: candidate artifact is missing, expired, or ambiguous")
print(valid[0]["id"])
