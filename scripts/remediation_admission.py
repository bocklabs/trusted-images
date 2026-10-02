"""Read-only, public-artifact admission before automatic promotion."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

REF = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[a-f0-9]{64}")
FIELDS = {"request_id", "app", "ref", "need_sha256", "producer_sha", "run_id",
          "run_attempt", "nonce", "issued_at", "repository", "workflow_ref"}
FINDING_FIELDS = {"id", "package", "installed", "class", "type", "target"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def findings_hash(findings):
    require(isinstance(findings, list) and 0 < len(findings) <= 1000, "invalid finding set")
    for item in findings:
        require(isinstance(item, dict) and set(item) == FINDING_FIELDS, "invalid finding identity")
        require(all(isinstance(v, str) and 0 < len(v) <= 512 and not any(ord(c) < 32 for c in v)
                    for v in item.values()), "invalid finding identity value")
    ordered = sorted(findings, key=canonical)
    require(findings == ordered and len({canonical(v) for v in findings}) == len(findings),
            "findings must be sorted and unique")
    return hashlib.sha256(canonical(findings).encode()).hexdigest()


def api(path):
    result = subprocess.run(["gh", "api", path], capture_output=True, timeout=45)
    require(result.returncode == 0, "GitHub API request failed")
    require(len(result.stdout) <= 2_000_000, "GitHub response too large")
    return json.loads(result.stdout)


def request_inputs():
    values = {"request_id": os.getenv("INPUT_REQUEST_ID", ""),
              "ref": os.getenv("INPUT_REF", ""), "need_sha256": os.getenv("INPUT_NEED_SHA256", "")}
    if not any(values.values()):
        return None
    require(all(values.values()), "remediation fields must be supplied together")
    require(re.fullmatch(r"[a-f0-9]{32}", values["request_id"]), "invalid request ID")
    require(REF.fullmatch(values["ref"]), "invalid immutable public reference")
    owner = os.environ["GITHUB_REPOSITORY"].split("/")[0].lower()
    require(values["ref"].startswith(f"ghcr.io/{owner}/{os.environ['INPUT_APP']}:"),
            "automatic reference must match the selected application")
    require(re.fullmatch(r"[a-f0-9]{64}", values["need_sha256"]), "invalid need hash")
    require(os.getenv("INPUT_FORCE_REPROMOTE", "false").lower() != "true" and
            not any(os.getenv(k) for k in ("INPUT_RECOVER_TAG", "INPUT_RECOVERY_RUN_ID", "INPUT_ACCEPTED_CANDIDATE_RUN_ID")),
            "automatic remediation cannot combine manual overrides")
    return values


def validate_readiness(receipt):
    require(isinstance(receipt, dict) and set(receipt) == FIELDS, "invalid readiness schema")
    for key, pattern in (("request_id", r"[a-f0-9]{32}"), ("need_sha256", r"[a-f0-9]{64}"),
                         ("producer_sha", r"[a-f0-9]{40}"), ("nonce", r"[a-f0-9]{64}"),
                         ("app", r"[a-z0-9][a-z0-9-]{0,79}"),
                         ("repository", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")):
        require(isinstance(receipt[key], str) and re.fullmatch(pattern, receipt[key]), "invalid readiness " + key)
    require(isinstance(receipt["ref"], str) and REF.fullmatch(receipt["ref"]), "invalid readiness reference")
    for key in ("run_id", "run_attempt", "issued_at"):
        require(type(receipt[key]) is int and receipt[key] > 0, "invalid readiness " + key)
    require(receipt["workflow_ref"] == receipt["repository"] + "/.github/workflows/promote.yaml@refs/heads/main",
            "readiness must use main promotion workflow")
    return receipt


def external_id(receipt):
    return "remediation:" + ":".join(str(receipt[k]) for k in ("request_id", "run_id", "run_attempt", "nonce"))


def prepare(path):
    request = request_inputs()
    if request is None:
        output("proceed", "manual promotion", False)
        return
    require(os.getenv("GITHUB_REF") == "refs/heads/main", "automatic promotion requires main")
    receipt = {**request, "app": os.environ["INPUT_APP"], "producer_sha": os.environ["GITHUB_SHA"],
               "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
               "nonce": secrets.token_hex(32), "issued_at": int(time.time()),
               "repository": os.environ["GITHUB_REPOSITORY"], "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"]}
    validate_readiness(receipt)
    require(receipt["run_attempt"] == 1, "automatic producer reruns require a fresh consumer request")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (canonical(receipt) + "\n").encode()
    path.write_bytes(content)
    path.with_name("SHA256SUMS").write_text(hashlib.sha256(content).hexdigest() + "  " + path.name + "\n")
    print(canonical({"app": receipt["app"], "ref": receipt["ref"], "reason": "readiness prepared"}))


def validate_verdict(check, receipt, run, app_id, now):
    app = check.get("app", {})
    require(type(app.get("id")) is int and app["id"] == app_id, "unauthorized App")
    require(isinstance(app.get("slug"), str) and app["slug"], "missing App actor")
    require(run.get("actor", {}).get("login") == app["slug"] + "[bot]" and
            run.get("triggering_actor", {}).get("login") == app["slug"] + "[bot]", "unauthorized installation actor")
    require(check.get("external_id") == external_id(receipt) and check.get("head_sha") == receipt["producer_sha"],
            "verdict identity mismatch")
    require(check.get("name") == "remediation-admission" and check.get("status") == "completed",
            "invalid check status")
    summary = check.get("output", {}).get("summary")
    require(isinstance(summary, str) and len(summary.encode()) <= 60_000, "invalid verdict summary")
    verdict = json.loads(summary)
    require(isinstance(verdict, dict) and set(verdict) == FIELDS | {"verdict", "expires_at", "findings", "artifact_id"},
            "invalid verdict schema")
    require(all(type(verdict.get(k)) is type(v) and verdict[k] == v
                for k, v in receipt.items() if k != "issued_at"), "verdict binding mismatch")
    require(type(verdict["issued_at"]) is int and receipt["issued_at"] <= verdict["issued_at"] <= now and
            type(verdict["expires_at"]) is int and now < verdict["expires_at"] <= verdict["issued_at"] + 120,
            "expired or pre-readiness verdict")
    require(verdict["verdict"] in ("proceed", "discard", "reuse", "block"), "unknown verdict")
    require(check.get("conclusion") == ("success" if verdict["verdict"] == "proceed" else "neutral"),
            "verdict conclusion mismatch")
    require(findings_hash(verdict["findings"]) == receipt["need_sha256"], "requested findings hash mismatch")
    require(type(verdict["artifact_id"]) is int and verdict["artifact_id"] > 0, "invalid verdict artifact")
    return verdict


def output(verdict, reason, force, receipt=None):
    result = {"verdict": verdict, "reason": reason, "force_repromote": force}
    if receipt:
        result.update({k: receipt[k] for k in ("app", "ref", "need_sha256", "request_id", "run_id", "run_attempt")})
    print(canonical(result))
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\nAutomatic admission: `" + canonical(result) + "`\n")
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"proceed={str(verdict == 'proceed').lower()}\nforce_repromote={str(force).lower()}\n")


def await_verdict(path, artifact_id, timeout):
    require(path.stat().st_size <= 100_000, "readiness exceeds bound")
    receipt = validate_readiness(json.loads(path.read_bytes()))
    request = request_inputs()
    require(request and all(receipt[k] == v for k, v in request.items()), "prepared request changed")
    require(receipt["run_attempt"] == 1 and all(str(receipt[k]) == os.environ[v] for k, v in
                (("producer_sha", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"),
                 ("run_attempt", "GITHUB_RUN_ATTEMPT"), ("repository", "GITHUB_REPOSITORY"),
                 ("workflow_ref", "GITHUB_WORKFLOW_REF"), ("app", "INPUT_APP"))), "prepared run changed")
    require(artifact_id.isdecimal() and int(artifact_id) > 0, "successful readiness upload required")
    app_id = int(os.environ["REMEDIATION_APP_ID"])
    require(app_id > 0, "configured App ID required")
    prefix = "repos/" + receipt["repository"]
    run = api(f"{prefix}/actions/runs/{receipt['run_id']}")
    require(run.get("path") == ".github/workflows/promote.yaml" and run.get("event") == "workflow_dispatch" and
            run.get("head_branch") == "main" and run.get("head_sha") == receipt["producer_sha"] and
            run.get("run_attempt") == receipt["run_attempt"] and run.get("status") == "in_progress",
            "untrusted producer run")
    artifact = api(f"{prefix}/actions/artifacts/{artifact_id}")
    expected = f"remediation-readiness-{receipt['request_id']}-{receipt['run_id']}-{receipt['run_attempt']}"
    require(artifact.get("name") == expected and artifact.get("expired") is False and
            artifact.get("workflow_run", {}).get("id") == receipt["run_id"] and
            artifact.get("workflow_run", {}).get("head_sha") == receipt["producer_sha"] and
            artifact.get("workflow_run", {}).get("head_branch") == "main", "upload identity mismatch")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        checks = []
        page = 1
        while True:
            response = api(f"{prefix}/commits/{receipt['producer_sha']}/check-runs?check_name=remediation-admission&filter=all&per_page=100&page={page}")
            entries = response["check_runs"]
            require(isinstance(entries, list), "invalid checks response")
            checks.extend(c for c in entries if c.get("external_id", "").startswith(
                f"remediation:{receipt['request_id']}:{receipt['run_id']}:"))
            if len(entries) < 100:
                break
            page += 1
            require(page <= 100, "excess check history")
        if checks:
            require(len(checks) == 1, "conflicting or replayed verdict")
            verdict = validate_verdict(checks[0], receipt, run, app_id, int(time.time()))
            require(str(verdict["artifact_id"]) == artifact_id, "verdict artifact mismatch")
            path.with_name("verdict.json").write_text(canonical(verdict) + "\n")
            output(verdict["verdict"], "authenticated post-lock verdict", verdict["verdict"] == "proceed", receipt)
            return
        time.sleep(min(15, max(0, deadline - time.monotonic())))
    output("block", "admission timed out", False, receipt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "await"))
    parser.add_argument("--output", type=Path, default=Path("readiness-artifact/readiness.json"))
    parser.add_argument("--artifact-id", default="")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    try:
        require(0 <= args.timeout <= 600, "timeout exceeds admission bound")
        if args.command == "prepare":
            prepare(args.output)
        else:
            await_verdict(args.output, args.artifact_id, args.timeout)
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "invalid admission evidence or API failure"
        output("block", reason, False)
        return 1


if __name__ == "__main__":
    sys.exit(main())
