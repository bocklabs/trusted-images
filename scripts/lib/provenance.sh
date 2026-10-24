#!/usr/bin/env bash
# Shared provenance helpers for local composite actions.

resolve_provenance() {
  local app="$1" tag="$2" out="$3"
  python3 scripts/reverify_signing.py --resolve "$app" --tag "$tag" > "${out}.tmp"
  mv "${out}.tmp" "$out"
}
