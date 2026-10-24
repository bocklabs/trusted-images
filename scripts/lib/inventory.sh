#!/usr/bin/env bash
# Shared inventory helpers for local composite actions.

emit_inventory_context() {
  local stage="$1" image="$2" app="$3" tag="${4:-}" out
  out="$(python3 scripts/promote_inventory.py "$stage" "$image" "$app" "$tag")"
  printf '%s\n' "$out"
  printf '%s\n' "$out" >> "$GITHUB_OUTPUT"
}
