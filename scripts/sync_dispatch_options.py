#!/usr/bin/env python3
"""Sync promote.yaml dispatch options with inventory/. Exits 1 on structural problems."""

import os
import pathlib
import re
import sys

WORKFLOW = pathlib.Path(".github/workflows/promote.yaml")


def emit_changed(changed: bool) -> None:
    if env_file := os.getenv("GITHUB_OUTPUT"):
        with open(env_file, "a") as stream:
            stream.write(f"changed={'true' if changed else 'false'}\n")


def main() -> int:
    apps = sorted(p.parent.name for p in pathlib.Path("inventory").glob("*/image.yaml"))
    if not apps:
        print("FATAL: no inventory entries found")
        return 1

    text = WORKFLOW.read_text()
    match = re.search(r"(# apps-begin\n)((?: {10}- .+\n)+)( {10}# apps-end)", text)
    if not match:
        print("FATAL: apps-block not found in promote.yaml")
        return 1

    current = re.findall(r"^\s+- (\S+)$", match.group(2), re.MULTILINE)
    if current == apps:
        print("options in sync")
        emit_changed(False)
        return 0

    WORKFLOW.write_text(
        text[: match.start(2)]
        + "".join(f"{' ' * 10}- {a}\n" for a in apps)
        + text[match.end(2) :]
    )
    added = [a for a in apps if a not in current]
    removed = [o for o in current if o not in apps]
    print(f"options updated: +{added} -{removed}")

    emit_changed(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
