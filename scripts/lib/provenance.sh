#!/usr/bin/env bash
# Shared provenance helpers for local composite actions.

resolve_provenance() {
  python3 scripts/reverify_signing.py --resolve "$APP" --tag "$INTERNAL_TAG" > "$1"
}
