#!/usr/bin/env python3
"""Stubbed-docker negative + happy suite for scripts/validate_image.py (D-15 layer 1).

Runs the validation CLI as a subprocess with a fake `docker` shim prepended
to PATH: the shim records every argv to a spool file, emits canned
image/container inspect JSON, probe statuses, and exit codes from a
per-test scenario file (scenarios are data, not per-test logic). No case
touches a real daemon. Every scenario uses short duration/timeout windows
(2-3s) so the whole suite stays in seconds. stdlib unittest only; no mock
library.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_IMAGE = REPO_ROOT / "scripts" / "validate_image.py"
APP = "postgres-exporter"
REF = "quay.io/example/app"
DIGEST = "sha256:" + "a1" * 32
REF_DIGEST = f"{REF}@{DIGEST}"

FAKE_DOCKER = """#!/usr/bin/env python3
\"\"\"Fake docker: spools argv, emits scenario-driven canned output.\"\"\"
import json
import os
import sys

SPOOL = os.environ["FAKE_DOCKER_SPOOL"]
SCENARIO = json.load(open(os.environ["FAKE_DOCKER_SCENARIO"]))
ARGS = sys.argv[1:]

with open(SPOOL, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(ARGS) + "\\n")


def next_from(key, default):
    seq = SCENARIO.get(key)
    if not seq:
        return default
    idx_file = SPOOL + f".{key}.idx"
    idx = 0
    if os.path.exists(idx_file):
        with open(idx_file, encoding="utf-8") as fh:
            idx = int(fh.read().strip() or 0)
    value = seq[idx] if idx < len(seq) else seq[-1]
    with open(idx_file, "w", encoding="utf-8") as fh:
        fh.write(str(idx + 1))
    return value


if ARGS[:2] == ["image", "inspect"]:
    print(json.dumps(SCENARIO.get("image_inspect", [])))
    raise SystemExit(0)

if ARGS[:1] == ["inspect"]:
    print(json.dumps([next_from("inspect_states", {"State": {"Running": True}})]))
    raise SystemExit(0)

if ARGS[:1] == ["logs"]:
    print(SCENARIO.get("logs", "fake container log line"))
    raise SystemExit(SCENARIO.get("logs_exit", 0))

if ARGS[:1] == ["rm"]:
    raise SystemExit(0)

if ARGS[:1] == ["run"]:
    rest = ARGS[1:]
    if "-d" in rest:
        print("fake-container-id")
        raise SystemExit(SCENARIO.get("run_detached_exit", 0))
    if any(arg.startswith("container:") for arg in rest):
        print(next_from("probe_statuses", "000"))
        raise SystemExit(0)
    print(SCENARIO.get("oneshot_stdout", ""))
    raise SystemExit(SCENARIO.get("oneshot_exit", 0))

raise SystemExit(0)
"""

INDEX_JSON = {"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}}]}


def image_inspect(healthcheck=None) -> list:
    return [
        {
            "Config": {
                "Entrypoint": ["/bin/app"],
                "Cmd": [],
                "Env": ["PATH=/usr/bin"],
                "Healthcheck": healthcheck,
            }
        }
    ]


def running(health_status=None) -> dict:
    state: dict = {"Running": True}
    if health_status is not None:
        state["Health"] = {"Status": health_status}
    return {"State": state}


class ValidateImageTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.bin_dir = self.tmp / "bin"
        self.bin_dir.mkdir()
        fake = self.bin_dir / "docker"
        fake.write_text(FAKE_DOCKER, encoding="utf-8")
        fake.chmod(0o755)
        self.spool = self.tmp / "docker-spool.jsonl"
        self.scenario_path = self.tmp / "scenario.json"
        self.index = self.tmp / "upstream-index.json"
        self.index.write_text(json.dumps(INDEX_JSON), encoding="utf-8")
        self.evidence_dir = self.tmp / "evidence"
        self.evidence = self.evidence_dir / "validation-evidence.json"

    def write_scenario(self, scenario: dict) -> None:
        self.scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    def run_cli(self, validation_type: str, extra: tuple = ()) -> subprocess.CompletedProcess:
        argv = [
            sys.executable,
            str(VALIDATE_IMAGE),
            "--app", APP,
            "--ref", REF,
            "--digest", DIGEST,
            "--validation-type", validation_type,
            "--index-file", str(self.index),
            "--evidence-out", str(self.evidence),
            *extra,
        ]
        env = os.environ.copy()
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env["FAKE_DOCKER_SPOOL"] = str(self.spool)
        env["FAKE_DOCKER_SCENARIO"] = str(self.scenario_path)
        env.pop("GITHUB_RUN_ID", None)
        return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)

    def load_evidence(self) -> dict:
        return json.loads(self.evidence.read_text(encoding="utf-8"))

    def spool_entries(self) -> list:
        lines = self.spool.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def assert_common_evidence(self, ev: dict) -> None:
        validation = ev["validation"]
        self.assertIn(validation["result"], ("pass", "fail"))
        for key in ("started_at", "finished_at", "duration_seconds"):
            self.assertIn(key, validation["timings"])
        baseline = validation["baseline"]
        for key in ("entrypoint", "cmd", "env", "platforms_index", "platforms_expected"):
            self.assertIn(key, baseline)
        self.assertEqual(baseline["entrypoint"], ["/bin/app"])
        self.assertEqual(baseline["platforms_index"], ["linux/amd64"])

    def assert_network_isolated(self) -> None:
        for entry in self.spool_entries():
            self.assertNotIn("-p", entry)
            self.assertNotIn("--publish", entry)
            if entry[:1] == ["run"]:
                self.assertIn("--network", entry)
                value = entry[entry.index("--network") + 1]
                self.assertTrue(
                    value == "none" or value.startswith("container:"),
                    f"non-isolated run in spool: {entry}",
                )

    def assert_container_removed(self) -> None:
        self.assertTrue(any(e[:2] == ["rm", "-f"] for e in self.spool_entries()))

    # --- negative cases (D-15 layer 1) ---

    def test_wrong_port_fails(self) -> None:
        self.write_scenario({"image_inspect": image_inspect(), "probe_statuses": ["000"]})
        result = self.run_cli(
            "http", ("--port", "9187", "--timeout-seconds", "2", "--duration-seconds", "2")
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-11", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assert_common_evidence(ev)
        self.assert_container_removed()
        log_file = self.evidence_dir / "validation-logs" / f"{APP}.log"
        self.assertTrue(log_file.is_file() and log_file.stat().st_size > 0)

    def test_oneshot_wrong_exit_fails(self) -> None:
        self.write_scenario({"image_inspect": image_inspect(), "oneshot_exit": 1})
        result = self.run_cli("oneshot", ("--expected-exit", "0", "--command", '["/bin/true"]'))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-11", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assert_common_evidence(ev)

    def test_process_crash_before_duration_fails(self) -> None:
        self.write_scenario(
            {"image_inspect": image_inspect(), "inspect_states": [{"State": {"Running": False}}]}
        )
        result = self.run_cli("process", ("--duration-seconds", "2"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-11", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assert_common_evidence(ev)
        self.assert_container_removed()

    def test_http_crash_after_probe_fails(self) -> None:
        self.write_scenario(
            {
                "image_inspect": image_inspect(),
                "probe_statuses": ["200"],
                "inspect_states": [{"State": {"Running": False}}],
            }
        )
        result = self.run_cli(
            "http", ("--port", "9187", "--timeout-seconds", "2", "--duration-seconds", "2")
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-11", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assert_common_evidence(ev)

    def test_health_stuck_starting_fails(self) -> None:
        self.write_scenario(
            {
                "image_inspect": image_inspect({"Test": ["CMD-SHELL", "true"]}),
                "probe_statuses": ["200"],
                "inspect_states": [running("starting")],
            }
        )
        result = self.run_cli(
            "http", ("--port", "9187", "--timeout-seconds", "2", "--duration-seconds", "2")
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-10", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assertTrue(ev["validation"]["health"]["defined"])
        self.assertEqual(ev["validation"]["health"]["final_status"], "starting")

    def test_health_unhealthy_fails_immediately(self) -> None:
        self.write_scenario(
            {
                "image_inspect": image_inspect({"Test": ["CMD-SHELL", "true"]}),
                "inspect_states": [running("unhealthy")],
            }
        )
        result = self.run_cli("process", ("--duration-seconds", "2"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("D-10", output)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "fail")
        self.assertEqual(ev["validation"]["health"]["final_status"], "unhealthy")
        self.assert_container_removed()

    # --- happy paths ---

    def test_happy_http_passes(self) -> None:
        self.write_scenario(
            {
                "image_inspect": image_inspect(),
                "probe_statuses": ["200"],
                "inspect_states": [running()],
            }
        )
        result = self.run_cli(
            "http", ("--port", "9187", "--timeout-seconds", "3", "--duration-seconds", "2")
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "pass")
        self.assertEqual(
            ev["validation"]["health"], {"defined": False, "final_status": "none-defined"}
        )
        self.assert_common_evidence(ev)
        self.assert_network_isolated()
        self.assert_container_removed()
        log_file = self.evidence_dir / "validation-logs" / f"{APP}.log"
        self.assertTrue(log_file.is_file() and log_file.stat().st_size > 0)

    def test_happy_process_passes(self) -> None:
        self.write_scenario(
            {"image_inspect": image_inspect(), "inspect_states": [running()]}
        )
        result = self.run_cli("process", ("--duration-seconds", "2"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "pass")
        self.assertEqual(
            ev["validation"]["health"], {"defined": False, "final_status": "none-defined"}
        )
        self.assert_common_evidence(ev)
        self.assert_network_isolated()
        self.assert_container_removed()

    def test_happy_oneshot_passes(self) -> None:
        self.write_scenario({"image_inspect": image_inspect(), "oneshot_exit": 0})
        result = self.run_cli("oneshot", ("--expected-exit", "0", "--command", '["/bin/true"]'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ev = self.load_evidence()
        self.assertEqual(ev["validation"]["result"], "pass")
        self.assertEqual(
            ev["validation"]["health"], {"defined": False, "final_status": "not-applicable"}
        )
        self.assertIn("log", ev["validation"]["logs_note"].lower())
        self.assert_common_evidence(ev)
        self.assert_network_isolated()

    # --- invocation-shape + usage contracts ---

    def test_oneshot_command_appended_after_image_ref(self) -> None:
        self.write_scenario({"image_inspect": image_inspect(), "oneshot_exit": 0})
        result = self.run_cli("oneshot", ("--expected-exit", "0", "--command", '["/bin/true"]'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        run_entries = [e for e in self.spool_entries() if e[:1] == ["run"]]
        self.assertTrue(run_entries)
        app_run = [e for e in run_entries if REF_DIGEST in e]
        self.assertTrue(app_run)
        entry = app_run[0]
        self.assertEqual(entry[-1], "/bin/true")
        self.assertEqual(entry[-2], REF_DIGEST)

    def test_http_without_port_exits_2(self) -> None:
        self.write_scenario({"image_inspect": image_inspect()})
        result = self.run_cli("http")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("--port", output)
        self.assertFalse(self.evidence.exists())


if __name__ == "__main__":
    unittest.main()
