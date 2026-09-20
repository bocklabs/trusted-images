#!/usr/bin/env python3
"""Validate one promoted candidate image: static checks + runtime profile.

Invoked by the promote workflow's validate job with the resolved inventory
entry (schema v2 spec.validation plus the workflow-side D-04 defaults).
Order of operations:

  1. Static checks (VAL-01/D-20/D-14): --index-file is the exact candidate
     image manifest (indexes are rejected), its runtime architecture must be
     exactly linux/amd64, and the candidate config must preserve the selected
     upstream child config except for additions to the four permitted OCI
     provenance labels. Manifest annotations are recorded separately.
  2. Runtime profile (VAL-02), selected by --validation-type:
       http      candidate runs detached under --network none (D-07); a
                 digest-pinned curl sidecar joins the candidate netns via
                 --network container:<name> and polls the port until
                 --expect-status within --timeout-seconds (2s interval);
                 then the D-11 post-probe liveness check applies.
       process   candidate runs detached under --network none and must
                 still be running when --duration-seconds elapses (D-11).
       oneshot   candidate runs blocking under the coreutils timeout
                 wrapper (--timeout-seconds) and must exit with a code
                 exactly equal to --expected-exit (D-11); the command argv
                 is appended after the image ref.
       Both long-running profiles (http, process) enforce the D-10 health
       gate: when the image defines a HEALTHCHECK the container must reach
       healthy within the stay-running window; unhealthy observed at any
       poll, or starting never reaching healthy by the deadline, fails.
       With no HEALTHCHECK defined the profile check is the sole gate and
       the evidence records none-defined — no health expectation is
       invented.
   3. Evidence: validation-evidence.json (--evidence-out) is written on
      EVERY exit path; a failed check writes result=fail evidence first,
      then prints a FATAL line naming the failed invariant, then exits 1
       (usage/config errors exit 2).


Docker container logs are appended incrementally to
<evidence-dir>/validation-logs/<app>.log on every poll iteration: with
--rm the container object vanishes on exit, so a post-mortem capture after
a crash would find nothing.

Untrusted-image execution happens only inside the ephemeral validate job on
a GitHub-hosted runner (ADR-004). Every docker interaction routes through a
single subprocess call site (docker() below) so the test suite can stub the
docker binary via PATH.

stdlib only.
"""

import argparse
import hashlib
import json
import copy
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CURL_IMAGE = "curlimages/curl:v8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"  # v8.22.0
PROFILES = ("http", "process", "oneshot")
POLL_INTERVAL_SECONDS = 2
LOGS_DIRNAME = "validation-logs"
# Pitfall 6: a oneshot container exits under --rm before any incremental
# docker logs capture can run — record the honest absence in the evidence
# instead of pretending a log artifact exists.
ONESHOT_LOG_NOTE = (
    "no incremental log capture: the oneshot container exits under --rm "
    "before docker logs can run; container output streams in the job log"
)
SHA256_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate one inventory candidate: static checks + runtime "
            "profile, validation-evidence.json out."
        ),
    )
    parser.add_argument("--app", required=True, help="inventory app name")
    parser.add_argument("--ref", required=True, help="candidate image ref")
    parser.add_argument(
        "--local-image",
        help="local candidate tag; config digest must match the exported manifest",
    )
    parser.add_argument(
        "--local-image-id", help="Docker image Id committed before OCI export"
    )
    parser.add_argument("--digest", required=True, help="candidate sha256:... digest")
    parser.add_argument("--baseline-ref", help="selected upstream child ref")
    parser.add_argument("--baseline-digest", help="selected upstream child digest")
    parser.add_argument(
        "--validation-type",
        required=True,
        choices=PROFILES,
        help="spec.validation.type",
    )
    parser.add_argument(
        "--port", type=int, default=None, help="http: port (required for http)"
    )
    parser.add_argument(
        "--path", default="/", help="http: request path (D-04 default /)"
    )
    parser.add_argument(
        "--expect-status",
        type=int,
        default=200,
        help="http: expected status (D-04 default 200)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=30,
        help="stay-running window (D-04 default 30)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="probe deadline (D-04 default 60)",
    )
    parser.add_argument(
        "--expected-exit",
        type=int,
        default=0,
        help="oneshot: expected exit code (D-04 default 0)",
    )
    parser.add_argument(
        "--expected-platforms",
        default="linux/amd64",
        help="comma list; each must be present in the index (D-04 default linux/amd64)",
    )
    parser.add_argument(
        "--command",
        default="[]",
        help="JSON array of argv appended after the image ref",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="candidate container env var; repeatable",
    )
    parser.add_argument(
        "--index-file", required=True, help="skopeo inspect --raw output (index JSON)"
    )
    parser.add_argument(
        "--evidence-out", required=True, help="path for validation-evidence.json"
    )
    return parser.parse_args()


def docker(*args: str) -> tuple[bool, str]:
    """Run one docker command; return (ok, output). Single subprocess call site."""
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    output = proc.stdout if proc.returncode == 0 else (proc.stderr or proc.stdout)
    return proc.returncode == 0, output.strip()


ALLOWED_NEW_LABELS = {
    "org.opencontainers.image.base.digest",
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.source",
    "org.opencontainers.image.version",
}
COMMIT_ARTIFACT_FIELDS = {"AttachStdout", "AttachStderr", "Hostname", "Image"}
IMAGE_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def label_drift(
    baseline: dict, candidate: dict, baseline_ref: str = "", baseline_digest: str = ""
) -> list[str]:
    base = baseline.get("Labels") or {}
    final = candidate.get("Labels") or {}
    if not isinstance(base, dict) or not isinstance(final, dict):
        return ["config Labels must be objects or null"]
    drift = [
        f"existing label {key!r} changed from {base[key]!r} to {final.get(key)!r}"
        for key in base
        if key not in final or final[key] != base[key]
    ]
    for key in final.keys() - base.keys():
        value = final[key]
        identifies_baseline = (
            key == "BaseImage"
            and isinstance(value, str)
            and baseline_ref
            and (
                value.startswith(f"{baseline_ref}:")
                or value == f"{baseline_ref}@{baseline_digest}"
            )
        )
        if identifies_baseline:
            continue
        if key not in ALLOWED_NEW_LABELS:
            drift.append(f"label {key!r} is not one of the permitted additions")
    return drift


def config_drift(
    baseline: dict, candidate: dict, baseline_ref: str = "", baseline_digest: str = ""
) -> list[str]:
    before = copy.deepcopy(baseline)
    after = copy.deepcopy(candidate)
    labels = label_drift(baseline, candidate, baseline_ref, baseline_digest)
    before.pop("Labels", None)
    after.pop("Labels", None)
    for field in COMMIT_ARTIFACT_FIELDS:
        before.pop(field, None)
        after.pop(field, None)
    drift = [
        f"runtime config changed outside permitted label additions: config field {key!r}"
        for key in sorted(set(before) | set(after))
        if before.get(key) != after.get(key)
    ]
    return drift + labels


def inspect_value(inspect_json: str, path: tuple[str, ...]):  # type: ignore[valid-type]
    """First-element JSON traversal; None when anything along the way is absent."""
    try:
        node = json.loads(inspect_json)[0]
        for key in path:
            node = node[key]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None
    return node


def append_logs(logs_path: Path, container_name: str) -> None:
    ok, out = docker("logs", container_name)
    logs_path.parent.mkdir(parents=True, exist_ok=True)
    with logs_path.open("a", encoding="utf-8") as fh:
        fh.write(out)
        if not ok:
            fh.write(
                f"\n[docker logs unavailable for {container_name} — exited before capture]\n"
            )


def sleep_until(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))


def wait_for_healthy(
    container_name: str,
    healthcheck_defined: bool,
    deadline: float,
    logs_path: Path,
    health: dict,
) -> str | None:
    """D-10 gate, shared by both long-running profiles.

    Polls .State.Health.Status on the named container only when the image
    config defines a Healthcheck: unhealthy (or gone) fails immediately;
    starting that has not reached healthy by the deadline fails with the
    stuck state named; healthy lands in evidence as final_status healthy.
    With no Healthcheck defined the profile check is the sole gate and
    evidence records none-defined (D-10 — no expectation invented).
    None on pass, FATAL reason on failure.
    """
    if not healthcheck_defined:
        health["final_status"] = "none-defined"
        return None
    while True:
        append_logs(logs_path, container_name)
        ok, out = docker("inspect", container_name)
        status = inspect_value(out, ("State", "Health", "Status")) if ok else "gone"
        if status == "healthy":
            health["final_status"] = "healthy"
            return None
        if status in ("unhealthy", "gone"):
            health["final_status"] = status
            return f"health gate failed: status '{status}' (D-10)"
        if time.monotonic() >= deadline:
            health["final_status"] = status if isinstance(status, str) else "unknown"
            return (
                f"health gate failed: stuck in '{status}' at the "
                f"durationSeconds deadline (D-10)"
            )
        sleep_until(deadline)


def docker_run_args(
    detached: bool,
    container_name: str,
    ref_digest: str,
    command: list[str],
    env_map: dict[str, str],
) -> list[str]:
    """docker run argv for a candidate container under --network none."""
    args = ["run", "--rm", "--name", container_name, "--network", "none"]
    if detached:
        args.insert(1, "-d")
    for key in sorted(env_map):
        args += ["-e", f"{key}={env_map[key]}"]
    return args + [ref_digest, *command]


def probe_http(args, container_name, logs_path):
    url = f"http://localhost:{args.port}{args.path}"
    expect = str(args.expect_status)
    probe_deadline = time.monotonic() + args.timeout_seconds
    last_status = "none"
    while time.monotonic() < probe_deadline:
        append_logs(logs_path, container_name)
        ok, out = docker(
            "run",
            "--rm",
            "--network",
            f"container:{container_name}",
            CURL_IMAGE,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        )
        last_status = out.strip() if ok else "sidecar-error"
        if last_status == expect:
            return None
        sleep_until(probe_deadline)
    append_logs(logs_path, container_name)
    if last_status != expect:
        return (
            f"http probe on {url} never returned {expect} within "
            f"{args.timeout_seconds}s (D-11); last status: {last_status}"
        )
    return None


def profile_longrunning(
    args: argparse.Namespace,
    container_name: str,
    ref_digest: str,
    command: list[str],
    env_map: dict[str, str],
    healthcheck_defined: bool,
    started_mono: float,
    logs_path: Path,
    health: dict,
) -> str | None:
    """D-07/D-08/D-10/D-11 http and process profiles.

    Both run the candidate detached under --network none and share the
    D-10 health gate, the stay-running window, and the D-11 liveness
    assert; the http profile additionally probes the port with a
    digest-pinned curl sidecar joined via --network container:<name>
    before the health gate applies. None on pass, FATAL reason on failure.
    """
    ok, out = docker(
        *docker_run_args(True, container_name, ref_digest, command, env_map)
    )
    if not ok:
        return f"candidate failed to start under --network none: {out}"
    try:
        if args.validation_type == "http":
            reason = probe_http(args, container_name, logs_path)
            if reason is not None:
                return reason
        deadline = started_mono + args.duration_seconds
        reason = wait_for_healthy(
            container_name, healthcheck_defined, deadline, logs_path, health
        )
        if reason is not None:
            return reason
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        append_logs(logs_path, container_name)
        ok, out = docker("inspect", container_name)
        running = inspect_value(out, ("State", "Running")) if ok else None
        if running is not True:
            return "container not running when durationSeconds elapsed (D-11)"
        return None
    finally:
        docker("rm", "-f", container_name)


def profile_oneshot(
    args: argparse.Namespace,
    container_name: str,
    ref_digest: str,
    command: list[str],
    env_map: dict[str, str],
) -> str | None:
    """D-08/D-11 oneshot profile. None on pass, FATAL reason on failure.

    Runs blocking under the coreutils timeout wrapper (D-08 runaway
    backstop — timeout kills the docker client; the job-level rm below and
    the VM teardown cover the container) and asserts exact exit-code
    equality with expectedExit (D-11 — no range, no tolerance).
    """
    run_args = docker_run_args(False, container_name, ref_digest, command, env_map)
    try:
        proc = subprocess.run(
            ["timeout", f"{args.timeout_seconds}s", "docker", *run_args],
            capture_output=True,
            text=True,
        )
    finally:
        docker("rm", "-f", container_name)
    actual = proc.returncode
    if actual != args.expected_exit:
        return f"oneshot exit code {actual} != expectedExit {args.expected_exit} (D-11)"
    return None


def runtime_inputs(args: argparse.Namespace) -> tuple[list[str], dict[str, str]]:
    expected_platforms = [
        p.strip() for p in args.expected_platforms.split(",") if p.strip()
    ]
    if expected_platforms != ["linux/amd64"]:
        raise ValueError("new candidates must validate exactly linux/amd64 (D-20)")
    try:
        command = json.loads(args.command)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--command is not valid JSON ({exc})") from exc
    if not isinstance(command, list) or not all(
        isinstance(item, str) for item in command
    ):
        raise ValueError("--command must be a JSON array of strings")
    env_map: dict[str, str] = {}
    for item in args.env:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"--env must be KEY=VALUE (got {item!r})")
        env_map[key] = value
    if args.validation_type == "http" and args.port is None:
        raise ValueError("the http profile requires --port (spec.validation.port)")
    return command, env_map


def load_manifest(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"index file not found: {path}")
    try:
        index = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"index file is not valid JSON ({exc})") from exc
    if not isinstance(index, dict):
        raise ValueError("candidate manifest is not an object (D-20)")
    if "manifests" in index:
        raise ValueError(
            "candidate manifest is an index; indexes cannot be published (D-20)"
        )
    if index.get("mediaType") not in IMAGE_MANIFEST_TYPES:
        raise ValueError(
            "candidate manifest is not an OCI/Docker image manifest (D-20)"
        )
    return index


def inspected_image(ref: str, parse_label: str) -> dict:
    ok, out = docker("image", "inspect", ref)
    if not ok:
        raise ValueError(f"docker image inspect failed for {ref}: {out}")
    try:
        inspected = json.loads(out)[0]
        config = inspected["Config"]
        if not isinstance(config, dict):
            raise TypeError("Config is not an object")
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"{parse_label} (VAL-01): {exc}") from exc
    return inspected


def local_candidate_error(
    args: argparse.Namespace, index: dict, index_path: Path, inspected: dict
) -> str | None:
    if not args.local_image:
        return None
    if not args.local_image_id or not SHA256_DIGEST_RE.fullmatch(args.local_image_id):
        return "--local-image-id must be the committed Docker image sha256:... Id"
    manifest_digest = "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
    if manifest_digest != args.digest:
        return "local candidate manifest digest does not match the exported bytes"
    descriptor = index.get("config")
    expected_config = descriptor.get("digest") if isinstance(descriptor, dict) else None
    if not isinstance(expected_config, str) or not SHA256_DIGEST_RE.fullmatch(
        expected_config
    ):
        return "local candidate OCI config descriptor is malformed"
    if inspected.get("Id") != args.local_image_id:
        return "local candidate image Id does not match --local-image-id"
    return None


def initial_evidence(args, command: str, env_map: dict) -> dict:
    return {
        "app": args.app,
        "validation": {
            "type": args.validation_type,
            "result": "pass",
            "params": {
                "type": args.validation_type,
                "port": args.port,
                "path": args.path,
                "expectStatus": args.expect_status,
                "durationSeconds": args.duration_seconds,
                "timeoutSeconds": args.timeout_seconds,
                "expectedExit": args.expected_exit,
                "command": command,
                "expectedPlatforms": [
                    p.strip() for p in args.expected_platforms.split(",") if p.strip()
                ],
                "env": env_map,
            },
            "timings": {},
            "health": {"defined": None, "final_status": "not-probed"},
            "runner": os.environ.get("RUNNER_NAME") or os.uname().nodename,
            "baseline": {
                "entrypoint": [],
                "cmd": [],
                "env": [],
                "platforms_expected": [
                    p.strip() for p in args.expected_platforms.split(",") if p.strip()
                ],
            },
        },
    }


def candidate_runtime_binding(
    args,
    index: dict,
    index_path,
    ev: dict,
    baseline_config,
    inspected: dict,
    ref_digest: str,
):
    config = inspected["Config"]
    if args.local_image:
        reason = local_candidate_error(args, index, index_path, inspected)
        if reason is not None:
            return reason, None, None
        manifest_digest = (
            "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
        )
        ref_digest = inspected["Id"]
        ev["validation"]["candidate_digest"] = manifest_digest
        ev["validation"]["candidate_image_id"] = inspected["Id"]
    if inspected.get("Os") != "linux" or inspected.get("Architecture") != "amd64":
        return (
            "candidate platform mismatch (D-20): expected linux/amd64, "
            f"got {inspected.get('Os')}/{inspected.get('Architecture')}",
            None,
            None,
        )
    if baseline_config is not None:
        drift = config_drift(
            baseline_config, config, args.baseline_ref or "", args.baseline_digest or ""
        )
        if drift:
            return "runtime configuration drift (D-14): " + "; ".join(drift), None, None
        ev["validation"]["baseline"]["config"] = baseline_config
        ev["validation"]["candidate_config"] = config
        ev["validation"]["config_drift"] = drift
    return None, ref_digest, config


def record_baseline_contract(ev: dict, config: dict, inspected: dict) -> bool:
    entrypoint = list(config.get("Entrypoint") or [])
    cmd = list(config.get("Cmd") or [])
    env = list(config.get("Env") or [])
    ev["validation"]["baseline"]["entrypoint"] = entrypoint
    ev["validation"]["baseline"]["cmd"] = cmd
    ev["validation"]["baseline"]["env"] = env
    ev["validation"][
        "candidate_platform"
    ] = f"{inspected['Os']}/{inspected['Architecture']}"
    ev["validation"]["health"]["defined"] = config.get("Healthcheck") is not None
    return config.get("Healthcheck") is not None


def validation_profile_reason(
    args,
    ev,
    ref_digest,
    command,
    env_map,
    container_name,
    healthcheck_defined,
    started_mono,
    logs_path,
):
    if args.validation_type == "oneshot":
        ev["validation"]["logs_note"] = ONESHOT_LOG_NOTE
        ev["validation"]["health"]["final_status"] = "not-applicable"
        return profile_oneshot(args, container_name, ref_digest, command, env_map)
    return profile_longrunning(
        args,
        container_name,
        ref_digest,
        command,
        env_map,
        healthcheck_defined,
        started_mono,
        logs_path,
        ev["validation"]["health"],
    )


def main() -> int:
    args = parse_args()
    started_wall = datetime.now(timezone.utc)
    started_mono = time.monotonic()

    try:
        command, env_map = runtime_inputs(args)
    except ValueError as exc:
        print(f"FATAL: {exc}")
        return 2

    evidence_out = Path(args.evidence_out)
    logs_path = evidence_out.parent / LOGS_DIRNAME / f"{args.app}.log"

    ev: dict = initial_evidence(args, command, env_map)

    def finish() -> None:
        finished = datetime.now(timezone.utc)
        ev["validation"]["timings"] = {
            "started_at": started_wall.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round((finished - started_wall).total_seconds(), 1),
        }
        evidence_out.parent.mkdir(parents=True, exist_ok=True)
        evidence_out.write_text(json.dumps(ev, indent=2) + "\n", encoding="utf-8")
        print(evidence_out)

    def fail(reason: str, code: int = 1) -> int:
        ev["validation"]["result"] = "fail"
        finish()
        print(f"FATAL: {reason}")
        return code

    index_path = Path(args.index_file)
    try:
        index = load_manifest(index_path)
    except ValueError as reason:
        return fail(str(reason))
    ev["validation"]["manifest_annotations"] = index.get("annotations") or {}

    baseline_ref_digest = (
        f"{args.baseline_ref}@{args.baseline_digest}"
        if args.baseline_ref and args.baseline_digest
        else None
    )
    baseline_config = None
    if baseline_ref_digest:
        try:
            baseline_config = inspected_image(
                baseline_ref_digest, "baseline image config does not parse"
            )["Config"]
        except ValueError as exc:
            return fail(str(exc))

    ref_digest = args.local_image or f"{args.ref}@{args.digest}"
    try:
        inspected = inspected_image(ref_digest, "image config does not parse")
    except ValueError as exc:
        return fail(str(exc))
    reason, ref_digest, config = candidate_runtime_binding(
        args, index, index_path, ev, baseline_config, inspected, ref_digest
    )
    if reason is not None:
        return fail(reason)

    healthcheck_defined = record_baseline_contract(ev, config, inspected)
    container_name = f"val-{args.app}-{os.environ.get('GITHUB_RUN_ID') or os.getpid()}"
    reason = validation_profile_reason(
        args,
        ev,
        ref_digest,
        command,
        env_map,
        container_name,
        healthcheck_defined,
        started_mono,
        logs_path,
    )
    if reason is not None:
        return fail(reason)
    finish()
    return 0


if __name__ == "__main__":
    sys.exit(main())
