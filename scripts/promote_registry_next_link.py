"""Read the next pagination link from registry headers."""

import re
from pathlib import Path

headers = Path("registry-page.headers").read_text(encoding="utf-8")
match = re.search(r'<([^>]+)>;\s*rel="next"', headers, re.IGNORECASE)
print(match.group(1) if match else "")
