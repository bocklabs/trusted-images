#!/usr/bin/env bash
# Shared workflow validation helpers for local composite actions.

require_app_name() {
  local app="$1"
  if [ -z "$app" ] || [[ "$app" == */* ]] || [[ "$app" == *..* ]]; then
    echo "FATAL: app not in inventory: ${app}"
    return 1
  fi
}
