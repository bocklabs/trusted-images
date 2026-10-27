#!/usr/bin/env bash
# Shared workflow validation helpers for local composite actions.

require_app_name() {
  local app="$1"
  if [[ ! "${app}" =~ ^[a-z0-9][a-z0-9._-]*$ ]]; then
    echo "FATAL: invalid app name: ${app}"
    return 1
  fi
}
