#!/usr/bin/env bash
# Shared publication-decision helpers for local composite actions.

write_published_decision() {
  local filter="$1"
  shift
  cp candidate-artifact/candidate-decision.json candidate-decision.json
  if ! jq "$@" "$filter" candidate-decision.json > candidate-decision.next.json; then
    rm -f candidate-decision.next.json
    echo "FATAL: decision filter failed" >&2
    return 1
  fi
  python3 scripts/promote_decision_integrity.py published candidate-decision.next.json || return
  mv candidate-decision.next.json candidate-decision.json
  printf 'decision_sha256=%s\n' "$(sha256sum candidate-decision.json | awk '{print $1}')" >> "${GITHUB_OUTPUT:-/dev/null}"
  printf 'now=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${GITHUB_OUTPUT:-/dev/null}"
}
