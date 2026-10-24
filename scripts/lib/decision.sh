#!/usr/bin/env bash
# Shared publication-decision helpers for local composite actions.

write_published_decision() {
  local filter="$1"
  shift
  cp candidate-artifact/candidate-decision.json candidate-decision.json
  jq "$@" "$filter" candidate-decision.json > candidate-decision.next.json
  mv candidate-decision.next.json candidate-decision.json
  python3 scripts/promote_decision_integrity.py published candidate-decision.json
  echo "decision_sha256=$(sha256sum candidate-decision.json | awk '{print $1}')" >> "$GITHUB_OUTPUT"
}
