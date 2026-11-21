"""Promotion dispatch for merged upstream pin changes."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/queue_inventory_promotions.py"


class InventoryPromotionTests(unittest.TestCase):
    def test_dispatches_only_updated_upstream_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

            def write(app, tag="1", digest="first", timeout=10):
                path = root / "inventory" / app / "image.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f"# Entrée\nspec:\n  upstream: {{ref: example/{app}, tag: '{tag}', digest: {digest}}}\n"
                    f"  validation: {{timeoutSeconds: {timeout}}}\n",
                    encoding="utf-8",
                )
                return path

            git("init", "-q")
            for app in ("tag-bump", "digest-refresh", "validation", "removed"):
                write(app)
            git("add", ".")
            git("-c", "user.name=CI", "-c", "user.email=ci@example.org", "commit", "-qm", "before")
            before = git("rev-parse", "HEAD")

            write("tag-bump", tag="2")
            write("digest-refresh", digest="second")
            write("validation", timeout=20)
            (root / "inventory/removed/image.yaml").unlink()
            write("new")
            git("add", ".")
            git("-c", "user.name=CI", "-c", "user.email=ci@example.org", "commit", "-qm", "after")
            after = git("rev-parse", "HEAD")

            gh = root / "gh"
            gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DISPATCH_LOG"\n', encoding="utf-8")
            gh.chmod(0o755)
            log = root / "dispatch.log"
            subprocess.run(
                [sys.executable, str(SCRIPT), before, after, "example/producer"],
                cwd=root,
                env={
                    **os.environ,
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "DISPATCH_LOG": str(log),
                    "LC_ALL": "C",
                    "PYTHONCOERCECLOCALE": "0",
                    "PYTHONUTF8": "0",
                },
                check=True,
            )
            self.assertCountEqual(
                log.read_text().splitlines(),
                [
                    "workflow run promote.yaml --repo example/producer --ref main -f app=tag-bump",
                    "workflow run promote.yaml --repo example/producer --ref main -f app=digest-refresh",
                ],
            )
