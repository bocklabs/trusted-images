#!/usr/bin/env bash
# Shared summary helpers for local composite actions.

append_promotion_summary() {
  python3 scripts/promote_summary.py >> "$GITHUB_STEP_SUMMARY" || return $?
}
