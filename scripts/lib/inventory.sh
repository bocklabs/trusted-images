#!/usr/bin/env bash
# Shared inventory helpers for local composite actions.

emit_inventory_context() {
  local stage="$1" image="$2" app="$3" tag="${4:-}" out key
  local -A seen=()
  out="$(python3 scripts/promote_inventory.py "$stage" "$image" "$app" "$tag")" || return
  while IFS= read -r line; do
    key="${line%%=*}"
    [ -z "${seen[$key]+x}" ] || { echo "FATAL: duplicate inventory output key" >&2; return 1; }
    case "$key" in
      upstream_ref|upstream_tag|upstream_digest|dest_package|patch_policy|app|validation_type|validation_port|validation_path|validation_expect_status|validation_duration_seconds|validation_timeout_seconds|validation_expected_exit|validation_command|validation_expected_platforms|validation_env) ;;
      *) echo "FATAL: invalid inventory output key" >&2; return 1 ;;
    esac
    seen[$key]=1
  done <<< "$out"
  printf '%s\n' "$out"
  printf '%s\n' "$out" >> "$GITHUB_OUTPUT"
}
