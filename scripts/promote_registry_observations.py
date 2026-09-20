"""Merge registry observations with trusted provenance."""

import json
import sys
from pathlib import Path

rows = []
for line in Path("registry-observations.tsv").read_text(encoding="utf-8").splitlines():
    tag, digest = line.split("\t")
    provenance = Path("provenance") / sys.argv[1] / f"{tag}.json"
    if provenance.is_file():
        record = json.loads(provenance.read_text(encoding="utf-8"))
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
                "upstream_index_digest": record["upstream"].get("index_digest")
                or record["upstream"].get("digest"),
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
