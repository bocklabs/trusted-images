"""Filter registry tags to immutable trusted revisions."""

import re
import sys
from pathlib import Path

pattern = re.compile(re.escape(sys.argv[1]) + r"-bocklabs\.[1-9][0-9]*$")
tags = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
for tag in tags:
    if pattern.fullmatch(tag):
        print(tag)
