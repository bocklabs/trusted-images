#!/usr/bin/env python3
"""Validate the producer remediation payload before promotion."""

import json
import os

from evaluate_promotion import requested_remediation

if __name__ == "__main__":
    requested_remediation(
        json.loads(os.environ["REQUESTED_REMEDIATION"]),
        os.environ["APP"],
    )
