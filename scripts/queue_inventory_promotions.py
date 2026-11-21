"""Queue standard promotions for changes to existing upstream pins."""

import subprocess
import sys
from collections.abc import Iterator
from pathlib import PurePosixPath

import yaml


def upstream(revision: str, path: str) -> object:
    blob = subprocess.check_output(["git", "show", f"{revision}:{path}"], encoding="utf-8")
    return yaml.safe_load(blob)["spec"]["upstream"]


def changed_apps(before: str, after: str) -> Iterator[str]:
    paths = subprocess.check_output(
        ["git", "diff", "--no-renames", "--diff-filter=M", "--name-only", "-z",
         before, after, "--", ":(glob)inventory/*/image.yaml"],
        encoding="utf-8",
    )
    for path in paths.split("\0")[:-1]:
        if upstream(before, path) != upstream(after, path):
            yield PurePosixPath(path).parent.name


def main() -> None:
    before, after, repo = sys.argv[1:]
    failed = []
    for app in changed_apps(before, after):
        result = subprocess.run(
            ["gh", "workflow", "run", "promote.yaml", "--repo", repo, "--ref", "main", "-f", f"app={app}"],
            check=False,
        )
        if result.returncode:
            failed.append(app)
    if failed:
        raise SystemExit("Could not queue promotion for: " + ", ".join(failed))


if __name__ == "__main__":
    main()
