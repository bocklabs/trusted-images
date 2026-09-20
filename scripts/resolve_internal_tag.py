"""Select an append-only internal tag from verified registry observations."""

import argparse
import json
import re
import sys
from pathlib import Path

DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
OBSERVATION_FIELDS = {
    "tag", "digest", "upstream_index_digest", "selected_child_digest", "platforms"
}


def validate_inputs(upstream_tag, upstream_digest, selected_child_digest, force_repromote, recover_tag, recover_candidate_digest):
    digests = (upstream_digest, selected_child_digest)
    if not upstream_tag or any(not isinstance(value, str) or not DIGEST_RE.fullmatch(value) for value in digests):
        raise ValueError("upstream tag, index digest, and selected child digest must be valid")
    if upstream_digest == selected_child_digest:
        raise ValueError("upstream index digest must differ from the selected child digest")
    if force_repromote and recover_tag:
        raise ValueError("force_repromote and recover_tag cannot be combined")
    if bool(recover_tag) != bool(recover_candidate_digest):
        raise ValueError("recover_tag and recover_candidate_digest must be supplied together")


def validate_observation(item, pattern, upstream_tag):
    if not isinstance(item, dict) or set(item) != OBSERVATION_FIELDS:
        raise ValueError("each observation must contain exactly the verified identity fields")
    tag, digest = item["tag"], item["digest"]
    index = item["upstream_index_digest"]
    child = item["selected_child_digest"]
    platforms = item["platforms"]
    if not isinstance(tag, str) or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ValueError("each observation must contain a valid tag and candidate digest")
    if platforms is not None and (not isinstance(platforms, list) or not all(isinstance(value, str) for value in platforms)):
        raise ValueError(f"observation platforms are invalid: {tag}")
    match = pattern.fullmatch(tag)
    if not match:
        raise ValueError(f"observation tag does not match {upstream_tag}-bocklabs.N: {tag}")
    if child is not None:
        validate_phase05_observation(tag, index, child, platforms)
    elif index not in ("", None):
        raise ValueError(f"historical observation cannot carry a Phase 05 index digest: {tag}")
    return tag, match


def validate_phase05_observation(tag, index, child, platforms):
    if not isinstance(index, str) or not DIGEST_RE.fullmatch(index):
        raise ValueError(f"Phase 05 observation lacks a valid index digest: {tag}")
    if not isinstance(child, str) or not DIGEST_RE.fullmatch(child) or child == index:
        raise ValueError(f"Phase 05 observation has an invalid child digest: {tag}")
    if platforms != ["linux/amd64"]:
        raise ValueError(f"Phase 05 observation is not linux/amd64-only: {tag}")


def recovered_revision(candidates, recover_tag, selected_child_digest, recover_candidate_digest):
    if recover_tag not in candidates:
        raise ValueError(f"recover_tag is not published: {recover_tag}")
    observed = candidates[recover_tag]
    if observed["selected_child_digest"] is None:
        raise ValueError("recover_tag is not a Phase 05 single-platform revision")
    if observed["selected_child_digest"] != selected_child_digest:
        raise ValueError("recover_tag selected child digest does not match this run")
    if observed["digest"] != recover_candidate_digest:
        raise ValueError("recover_tag digest does not match the trusted candidate digest")


def allocated_revision(upstream_tag, ordered, upstream_digest, selected_child_digest, force_repromote):
    phase05 = [item for item in ordered if item["selected_child_digest"] is not None]
    if not force_repromote:
        matching = [item for item in phase05 if item["selected_child_digest"] == selected_child_digest]
        if matching:
            reused = matching[0]
            return reused["tag"], True, reused["upstream_index_digest"] != upstream_digest, False

    next_revision = ordered[0]["revision"] + 1 if ordered else 1
    comparison = phase05[0] if phase05 else None
    higher_upstream = comparison is not None and comparison["upstream_index_digest"] != upstream_digest
    original_child_selected = (
        comparison is not None and comparison["selected_child_digest"] != selected_child_digest
    )
    return f"{upstream_tag}-bocklabs.{next_revision}", False, higher_upstream, original_child_selected


def select_internal_tag(
    upstream_tag: str,
    upstream_digest: str,
    selected_child_digest: str,
    observations: object,
    force_repromote: bool = False,
    recover_tag: str = "",
    recover_candidate_digest: str = "",
) -> tuple[str, bool, bool, bool]:
    """Return (tag, skip_copy, higher_upstream, original_child_selected)."""
    validate_inputs(upstream_tag, upstream_digest, selected_child_digest, force_repromote, recover_tag, recover_candidate_digest)
    if not isinstance(observations, list):
        raise ValueError("observations must be a JSON array")

    pattern = re.compile(re.escape(upstream_tag) + r"-bocklabs\.([1-9][0-9]*)$")
    candidates: dict[str, dict] = {}
    for item in observations:
        tag, match = validate_observation(item, pattern, upstream_tag)
        if tag in candidates:
            raise ValueError(f"duplicate observation for tag: {tag}")
        candidates[tag] = {"revision": int(match.group(1)), **item}

    ordered = sorted(candidates.values(), key=lambda item: item["revision"], reverse=True)
    if recover_tag:
        recovered_revision(candidates, recover_tag, selected_child_digest, recover_candidate_digest)
        return recover_tag, True, False, False
    return allocated_revision(upstream_tag, ordered, upstream_digest, selected_child_digest, force_repromote)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-tag", required=True)
    parser.add_argument("--upstream-digest", required=True)
    parser.add_argument("--selected-child-digest", required=True)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--force-repromote", action="store_true")
    parser.add_argument("--recover-tag", default="")
    parser.add_argument("--recover-candidate-digest", default="")
    args = parser.parse_args()
    try:
        observations = json.loads(args.observations.read_text(encoding="utf-8"))
        internal_tag, skip_copy, higher_upstream, original_child_selected = select_internal_tag(
            args.upstream_tag,
            args.upstream_digest,
            args.selected_child_digest,
            observations,
            args.force_repromote,
            args.recover_tag,
            args.recover_candidate_digest,
        )
    except (OSError, ValueError) as exc:
        print(f"[tag] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "internal_tag": internal_tag,
        "skip_copy": skip_copy,
        "supersedes": {
            "higher_upstream": higher_upstream,
            "original_child_selected": original_child_selected,
        },
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
