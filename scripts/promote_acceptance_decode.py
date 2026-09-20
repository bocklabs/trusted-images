"""Decode base64 acceptance content from the GitHub API."""

import base64
import json
from pathlib import Path

value = json.loads(Path("acceptance-content.json").read_text())
encoded = value.get("content", "")
if value.get("encoding") != "base64" or not isinstance(encoded, str):
    raise SystemExit("FATAL: acceptance content API did not return base64 bytes")
encoded = encoded.replace("\n", "")
Path("acceptance.json").write_bytes(base64.b64decode(encoded, validate=True))
