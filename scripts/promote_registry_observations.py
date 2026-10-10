"""Merge registry observations with trusted provenance."""

import json
import sys
import re
from pathlib import Path
from reverify_signing import merged_commit, resolve_record

rows = []
commit = merged_commit()
for line in Path("registry-observations.tsv").read_text(encoding="utf-8").splitlines():
    tag, digest = line.split("\t")
    provenance = resolve_record(sys.argv[1], tag, commit) if re.fullmatch(r"[^/]+-bocklabs\.[1-9][0-9]*", tag) else None
    if provenance is not None:
        record = json.loads(provenance)
        if (
            record.get("schema") != "trusted-images.bocklabs.dev/provenance-v1"
            or record.get("internal", {}).get("tag") != tag
            or record.get("internal", {}).get("digest") != digest
        ):
            raise SystemExit(f"FATAL: provenance does not bind observed tag {tag}")
        rows.append(
            {
                "tag": tag,
                "digest": digest,
                "upstream_index_digest": record["upstream"].get("index_digest") or "",
                "selected_child_digest": record["upstream"].get(
                    "selected_child_digest"
                ),
                "platforms": record["internal"]["platforms"],
            }
        )
    else:
        rows.append(
            {
                "tag": tag,
                "digest": digest,
                "upstream_index_digest": "",
                "selected_child_digest": None,
                "platforms": None,
            }
        )
print(json.dumps(rows))
