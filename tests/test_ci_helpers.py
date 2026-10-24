"""Contract tests for shared shell helpers used by local actions."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CiHelperTests(unittest.TestCase):
    def workspace(self, root: Path) -> None:
        (root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)

    def run_bash(self, script: str, *, cwd: Path, env: dict[str, str] | None = None):
        return subprocess.run(
            ["bash", "-c", script],
            cwd=cwd,
            env={**os.environ, **(env or {})},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_ghcr_pull_token_handles_success_denied_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
out = pathlib.Path(args[args.index("-o") + 1])
if os.environ["MODE"] == "success":
    out.write_text('{"token":"abc"}')
    print("200")
elif os.environ["MODE"] == "denied":
    out.write_text('{"errors":[{"code":"DENIED"}]}')
    print("403")
    sys.exit(22)
else:
    out.write_text("{}")
    print("502")
    sys.exit(22)
"""
            )
            curl.chmod(0o755)
            script = (
                "source scripts/lib/ghcr.sh; "
                'ghcr_pull_token app token.json'
            )
            env = {"PATH": f"{bin_dir}:{os.environ['PATH']}"}

            success = self.run_bash(script, cwd=root, env={**env, "MODE": "success"})
            self.assertEqual(success.returncode, 0)
            self.assertEqual(success.stdout, "abc\n")

            denied = self.run_bash(script, cwd=root, env={**env, "MODE": "denied"})
            self.assertEqual(denied.returncode, 0)
            self.assertEqual(denied.stdout, "")

            failed = self.run_bash(script, cwd=root, env={**env, "MODE": "failure"})
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("GHCR token request failed", failed.stderr)

    def test_ghcr_require_pull_token_rejects_denied_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
pathlib.Path(args[args.index("-o") + 1]).write_text('{"errors":[{"code":"DENIED"}]}')
print("403")
sys.exit(22)
"""
            )
            curl.chmod(0o755)
            result = self.run_bash(
                "source scripts/lib/ghcr.sh; ghcr_require_pull_token app token.json",
                cwd=root,
                env={"PATH": f"{bin_dir}:{os.environ['PATH']}"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not readable", result.stderr)

    def test_skopeo_authfile_follows_registry_reference(self) -> None:
        script = (
            "source scripts/lib/registry.sh; "
            'set_skopeo_auth "$REF"; '
            'if [ "${#SKOPEO_AUTH[@]}" -gt 0 ]; then printf "%s\\n" "${SKOPEO_AUTH[@]}"; '
            'jq -r .auths[].auth "$SKOPEO_AUTHFILE" | base64 -d; fi'
        )
        env = {"DOCKERHUB_USERNAME": "user", "DOCKERHUB_TOKEN": "secret"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            for ref in ("docker.io/library/alpine", "alpine", "grafana/grafana"):
                with self.subTest(ref=ref):
                    dockerhub = self.run_bash(
                        script, cwd=root, env={**env, "REF": ref}
                    )
                    self.assertEqual(
                        dockerhub.stdout.splitlines(),
                        ["--src-authfile", "/run/skopeo-auth.json", "user:secret"],
                    )
            for ref in ("quay.io/example/app", "ghcr.io/example/app", "localhost/app"):
                with self.subTest(ref=ref):
                    external = self.run_bash(script, cwd=root, env={**env, "REF": ref})
                    self.assertEqual(external.stdout, "")

    def test_inventory_context_rejects_duplicate_output_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\nprintf 'upstream_ref=a\\nupstream_ref=b\\n'\n")
            python.chmod(0o755)
            output = root / "github-output"
            output.write_text("")
            result = self.run_bash(
                "source scripts/lib/inventory.sh; emit_inventory_context candidate image app",
                cwd=root,
                env={
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "GITHUB_OUTPUT": str(output),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FATAL: duplicate inventory output key", result.stderr)
            self.assertEqual(output.read_text(), "")

    def test_app_name_allowlist_rejects_paths_and_shell_metacharacters(self) -> None:
        script = 'source scripts/lib/validate.sh; require_app_name "$APP"'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            for app in ("example", "example.app", "example-app_1"):
                with self.subTest(app=app):
                    result = self.run_bash(script, cwd=root, env={"APP": app})
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for app in ("../example", "-x", "example app", "example/name", ""):
                with self.subTest(app=app):
                    result = self.run_bash(script, cwd=root, env={"APP": app})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("invalid app name", result.stdout)

    def test_load_oci_archive_returns_loaded_image_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text(
                """#!/bin/sh
case "$1 $2" in
  "image inspect") printf '%s\\n' sha256:image ;;
  "run "*) exit 0 ;;
  "load "*) exit 0 ;;
  *) exit 9 ;;
esac
"""
            )
            docker.chmod(0o755)
            result = self.run_bash(
                "source scripts/lib/oci.sh; load_oci_archive skopeo archive.tar target:tag",
                cwd=root,
                env={"PATH": f"{bin_dir}:{os.environ['PATH']}"},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), "sha256:image")

    def test_write_published_decision_uses_integrity_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            artifact = root / "candidate-artifact"
            artifact.mkdir()
            (artifact / "candidate-decision.json").write_text(
                json.dumps({"published": {}, "provenance": {"merged": False}})
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            output = root / "output"
            script = (
                "source scripts/lib/decision.sh; "
                "write_published_decision '.published.digest = $digest' --arg digest sha256:abc"
            )
            result = self.run_bash(
                script,
                cwd=root,
                env={
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "GITHUB_OUTPUT": str(output),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                json.loads((root / "candidate-decision.json").read_text())["published"]["digest"],
                "sha256:abc",
            )
            self.assertRegex(output.read_text(), r"decision_sha256=[a-f0-9]{64}")
            self.assertRegex(output.read_text(), r"(?m)^now=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_write_published_decision_preserves_original_on_integrity_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.workspace(root)
            artifact = root / "candidate-artifact"
            artifact.mkdir()
            original = {"published": {}, "provenance": {"merged": False}}
            (artifact / "candidate-decision.json").write_text(json.dumps(original))
            bin_dir = root / "bin"
            bin_dir.mkdir()
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\nexit 1\n")
            python.chmod(0o755)
            result = self.run_bash(
                "source scripts/lib/decision.sh; "
                "write_published_decision '.published.digest = $digest' --arg digest sha256:abc",
                cwd=root,
                env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(root / "output")},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                json.loads((root / "candidate-decision.json").read_text()),
                original,
            )


if __name__ == "__main__":
    unittest.main()
