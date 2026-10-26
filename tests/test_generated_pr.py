"""Exercise generated-PR write-back with a local Git remote."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class GeneratedPRTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "work"
        self.work.mkdir()
        self.remote = self.root / "remote.git"
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Reviewer")
        self.git("config", "user.email", "reviewer@example.invalid")
        (self.work / "inventory").mkdir()
        (self.work / "inventory/evidence.json").write_text("original\n")
        self.git("add", ".")
        self.git("commit", "-m", "initial")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "main")
        command = self.root / "gh"
        command.write_text('#!/bin/sh\nif [ "$2" = create ]; then echo https://github.com/example/repo/pull/1; fi\n')
        command.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "GH_TOKEN": "test",
            "BRANCH": "chore/generated",
            "PATHS": "inventory",
            "COMMIT_MESSAGE": "chore: generate evidence",
            "PR_TITLE": "generated",
            "PR_BODY": "generated",
            "GITHUB_OUTPUT": str(self.root / "output"),
        }

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.work, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def run_action(self):
        action = yaml.safe_load((ROOT / ".github/actions/validate/push-generated-pr/action.yaml").read_text())
        (self.work / "inventory/evidence.json").write_text("generated\n")
        return subprocess.run(
            ["bash", "-c", action["runs"]["steps"][0]["run"]],
            cwd=self.work, env=self.env, check=False, capture_output=True, text=True,
        )

    def test_pushes_generated_files_and_reports_exact_remote_head(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        head = self.git("rev-parse", "HEAD")
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/chore/generated").split()[0], head)
        self.assertIn(f"head_sha={head}", (self.root / "output").read_text())
        self.assertIn("pr_url=https://github.com/example/repo/pull/1", (self.root / "output").read_text())

    def test_preserves_human_commits_on_existing_generated_branch(self):
        self.git("checkout", "-b", "chore/generated")
        (self.work / "inventory/evidence.json").write_text("human edit\n")
        self.git("commit", "-am", "review correction")
        head = self.git("rev-parse", "HEAD")
        self.git("push", "origin", "chore/generated")
        self.git("checkout", "main")
        result = self.run_action()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("human commits", result.stdout)
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/chore/generated").split()[0], head)

    def test_applies_retained_patch_only_at_its_source_commit(self):
        artifact = self.work / "published-rescan"
        artifact.mkdir()
        evidence = self.work / "inventory/evidence.json"
        evidence.write_text("generated\n")
        (artifact / "go-evidence.patch").write_text(self.git("diff") + "\n")
        self.git("restore", "inventory/evidence.json")
        action = yaml.safe_load((ROOT / ".github/actions/validate/apply-go-evidence/action.yaml").read_text())
        head = self.git("rev-parse", "HEAD")
        for source_sha, expected in (("stale", 1), (head, 0)):
            (artifact / "selection.json").write_text(json.dumps({"source_sha": source_sha}))
            (artifact / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("go-evidence.patch", "selection.json")
            ))
            result = subprocess.run(
                ["bash", "-c", action["runs"]["steps"][0]["run"]],
                cwd=self.work, env={**self.env, "GITHUB_SHA": head},
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(evidence.read_text(), "original\n" if expected else "generated\n")
