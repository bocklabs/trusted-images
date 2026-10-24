#!/usr/bin/env bash
# Shared provenance helpers for local composite actions.

resolve_provenance() {
  local app="$1" tag="$2" out="$3"
  rm -f "${out}" "${out}.tmp"
  python3 scripts/reverify_signing.py --resolve "$app" --tag "$tag" > "${out}.tmp" || {
    rm -f "${out}.tmp"
    return 1
  }
  mv "${out}.tmp" "$out"
}
