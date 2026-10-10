"""Refresh only armed release-App current-record PRs after validated main pushes."""

import json
import os
import re
import subprocess
import sys

from promote_signing_gate import load_identity
from reverify_signing import ROOT, git, git_record, load_current, merged_commit, replacement


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def owned_current(pull, repo):
    head = pull.get("head", {})
    owner = head.get("repo") or {}
    return (pull.get("auto_merge") is not None and pull.get("user", {}).get("login") == "bocklabs-release[bot]"
            and pull.get("base", {}).get("ref") == "main" and owner.get("full_name") == repo
            and re.fullmatch(r"provenance/current/[a-z0-9][a-z0-9._-]*", head.get("ref", "")))


def validate_head(pull, main, identity):
    head = pull["head"]["sha"]
    app = pull["head"]["ref"].rsplit("/", 1)[1]
    path = f"provenance/{app}/current.json"
    if git("diff", "--name-only", f"{main}...{head}").decode().splitlines() != [path]:
        raise ValueError("provenance PR changes files outside its current record")
    author = git("log", "-1", "--format=%ae", head).decode().strip()
    if author != "302587774+bocklabs-release[bot]@users.noreply.github.com":
        raise ValueError("provenance PR head is not owned by release App")
    candidate = git("show", f"{head}:{path}")
    previous = load_current(app, main)
    if not replacement(previous, json.loads(candidate), app, identity) and candidate != git_record(main, path):
        raise ValueError("same identity must preserve current bytes")
    return app


def require_main(main):
    rows = git("ls-remote", "origin", "refs/heads/main").decode().splitlines()
    if len(rows) != 1 or rows[0].split() != [main, "refs/heads/main"]:
        raise ValueError("validated main changed or unavailable; remaining refreshes stopped")


def refresh_pull(pull, repo, main, identity):
    head = pull["head"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("invalid provenance PR head")
    git("fetch", "origin", head)
    if git("merge-base", main, head).decode().strip() == main:
        return
    app = validate_head(pull, main, identity)
    latest = json.loads(gh("api", f"repos/{repo}/pulls/{pull['number']}"))
    if not owned_current(latest, repo) or latest["head"]["sha"] != head or merged_commit() != main:
        raise ValueError("provenance head or validated main changed before refresh")
    require_main(main)
    gh("api", "--method", "PUT", f"repos/{repo}/pulls/{pull['number']}/update-branch", "-f", f"expected_head_sha={head}")
    print(f"refresh requested for {app} PR {pull['number']} at {head}")


def refresh(repo):
    pages = json.loads(gh("api", "--paginate", "--slurp", f"repos/{repo}/pulls?state=open&base=main&per_page=100"))
    main = merged_commit()
    if git("rev-parse", "HEAD").decode().strip() != main:
        raise ValueError("validated main checkout is stale")
    require_main(main)
    identity = load_identity(ROOT / "config/signing-identity.json")
    failures = []
    for pull in (p for page in pages for p in page):
        if not owned_current(pull, repo):
            continue
        if merged_commit() != main:
            raise ValueError("validated main changed; remaining refreshes stopped")
        require_main(main)
        try:
            refresh_pull(pull, repo, main, identity)
        except (ValueError, subprocess.CalledProcessError) as error:
            failure = f"PR {pull['number']} ({pull['head']['ref']}): {error}"
            failures.append(failure)
            print(failure, file=sys.stderr)
        if merged_commit() != main:
            raise ValueError("validated main changed; remaining refreshes stopped")
        require_main(main)
    if failures:
        raise ValueError("current provenance refresh failures: " + "; ".join(failures))


if __name__ == "__main__":
    refresh(os.environ["GITHUB_REPOSITORY"])
