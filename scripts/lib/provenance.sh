#!/usr/bin/env bash
# Shared provenance helpers for local composite actions.

resolve_provenance() {
  local app="$1" tag="$2" out="$3"
  rm -f "${out}.tmp"
  python3 scripts/reverify_signing.py --resolve "$app" --tag "$tag" > "${out}.tmp" || {
    rm -f "${out}.tmp"
    echo "FATAL: provenance resolution failed for ${app}:${tag}" >&2
    return 1
  }
  rm -f "${out}"
  mv "${out}.tmp" "$out"
}
