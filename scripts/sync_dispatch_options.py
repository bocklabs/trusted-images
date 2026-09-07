#!/usr/bin/env python3
"""Sync promote.yaml dispatch options with inventory/. Exits 1 on structural problems."""

import os
import pathlib
import re
import sys

WORKFLOW = pathlib.Path(".github/workflows/promote.yaml")


def main() -> int:
    apps = sorted(p.parent.name for p in pathlib.Path("inventory").glob("*/image.yaml"))
    if not apps:
        print("FATAL: no inventory entries found")
        return 1

    text = WORKFLOW.read_text()
    match = re.search(r"(# apps-begin\n)((?:          - .+\n)+)(          # apps-end)", text)
    if not match:
        print("FATAL: apps-block not found in promote.yaml")
        return 1

    current = re.findall(r"^\s+- (\S+)$", match.group(2), re.M)
    if current == apps:
        print("options in sync")
        return 0

    WORKFLOW.write_text(text[: match.start(2)] + "".join(f"          - {a}\n" for a in apps) + text[match.end(2) :])
    added = [a for a in apps if a not in current]
    removed = [o for o in current if o not in apps]
    print(f"options updated: +{added} -{removed}")

    env_file = os.getenv("GITHUB_OUTPUT")
    if env_file:
        with open(env_file, "a") as f:
            f.write("changed=true\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
