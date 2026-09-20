"""Build fail-closed GitHub acceptance evidence."""

import hashlib
import json
import os
import sys
from pathlib import Path

path = sys.argv[1]
repository = os.environ["REPO"]
content = json.loads(Path("acceptance-content.json").read_text())
commits = json.loads(Path("acceptance-commits.json").read_text())
commit_detail = json.loads(Path("acceptance-commit.json").read_text())
associated = json.loads(Path("acceptance-prs.json").read_text())
pull = json.loads(Path("acceptance-pr.json").read_text())
issue = json.loads(Path("acceptance-issue.json").read_text())
if len(commits) != 1 or content.get("path") != path:
    raise SystemExit("FATAL: acceptance commit/path is ambiguous")
changed = [
    value
    for value in commit_detail.get("files", [])
    if value.get("filename") == path and value.get("sha") == content.get("sha")
]
if commit_detail.get("sha") != commits[0]["sha"] or len(changed) != 1:
    raise SystemExit("FATAL: acceptance commit does not bind the current file bytes")


def pull_proof(value):
    return {
        "number": value["number"],
        "html_url": value["html_url"],
        "state": value["state"],
        "merged": value["merged"] is True,
        "merged_at": value["merged_at"],
        "merged_by": {"login": value["merged_by"]["login"]},
        "base_repository": value["base"]["repo"]["full_name"],
        "base_ref": value["base"]["ref"],
    }


def issue_proof(value):
    return {
        "number": value["number"],
        "html_url": value["html_url"],
        "state": value["state"],
        "is_pull_request": "pull_request" in value,
    }


if (
    pull.get("state") != "closed"
    or pull.get("merged") is not True
    or not pull.get("merged_at")
    or pull.get("base", {}).get("repo", {}).get("full_name") != repository
    or pull.get("base", {}).get("ref") != "main"
    or not any(value.get("number") == pull.get("number") for value in associated)
):
    raise SystemExit(
        "FATAL: acceptance pull request is not a merged main-branch approval"
    )

proof = {
    "repository": repository,
    "path": path,
    "record_sha256": hashlib.sha256(Path("acceptance.json").read_bytes()).hexdigest(),
    "content_blob_sha": content["sha"],
    "commit": {"sha": commits[0]["sha"], "path": path, "blob_sha": content["sha"]},
    "associated_pull_requests": [pull_proof(value) for value in associated],
    "pull_request": pull_proof(pull),
    "issue": issue_proof(issue),
}
Path("github-evidence.json").write_text(json.dumps(proof, indent=2) + "\n")
