"""Select an append-only internal tag from verified registry observations."""

import argparse
import json
import re
import sys
from pathlib import Path

DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def select_internal_tag(
    upstream_tag: str,
    upstream_digest: str,
    observations: object,
    force_repromote: bool = False,
    recover_tag: str = "",
) -> tuple[str, bool]:
    """Return (tag, skip_copy) without reading a registry."""
    if not upstream_tag or not DIGEST_RE.fullmatch(upstream_digest):
        raise ValueError("upstream tag and digest must be valid")
    if force_repromote and recover_tag:
        raise ValueError("force_repromote and recover_tag cannot be combined")
    if not isinstance(observations, list):
        raise ValueError("observations must be a JSON array")

    pattern = re.compile(re.escape(upstream_tag) + r"-bocklabs\.([1-9][0-9]*)$")
    candidates: dict[str, tuple[int, str]] = {}
    for item in observations:
        if not isinstance(item, dict) or set(item) != {"tag", "digest"}:
            raise ValueError("each observation must contain only tag and digest")
        tag, digest = item["tag"], item["digest"]
        if not isinstance(tag, str) or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise ValueError("each observation must contain a valid tag and digest")
        match = pattern.fullmatch(tag)
        if not match:
            raise ValueError(f"observation tag does not match {upstream_tag}-bocklabs.N: {tag}")
        if tag in candidates:
            raise ValueError(f"duplicate observation for tag: {tag}")
        candidates[tag] = (int(match.group(1)), digest)

    if recover_tag:
        if not pattern.fullmatch(recover_tag):
            raise ValueError("recover_tag must match the pinned upstream tag")
        if recover_tag not in candidates:
            raise ValueError(f"recover_tag is not published: {recover_tag}")
        if candidates[recover_tag][1] != upstream_digest:
            raise ValueError("recover_tag digest does not match the pinned upstream digest")
        return recover_tag, True

    ordered = sorted(candidates.items(), key=lambda item: item[1][0], reverse=True)
    if not force_repromote:
        for tag, (_, digest) in ordered:
            if digest == upstream_digest:
                return tag, True
    next_revision = ordered[0][1][0] + 1 if ordered else 1
    return f"{upstream_tag}-bocklabs.{next_revision}", False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-tag", required=True)
    parser.add_argument("--upstream-digest", required=True)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--force-repromote", action="store_true")
    parser.add_argument("--recover-tag", default="")
    args = parser.parse_args()
    try:
        observations = json.loads(args.observations.read_text(encoding="utf-8"))
        internal_tag, skip_copy = select_internal_tag(
            args.upstream_tag,
            args.upstream_digest,
            observations,
            args.force_repromote,
            args.recover_tag,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[tag] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"internal_tag": internal_tag, "skip_copy": skip_copy}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
