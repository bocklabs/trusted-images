#!/usr/bin/env bash
# Shared GHCR helpers for local composite actions.

GHCR_MANIFEST_ACCEPT='application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
GHCR_INDEX_ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

ghcr_pull_token() {
  local app="$1" response="$2" TOKEN_STATUS CURL_STATUS
  set +e
  TOKEN_STATUS="$(curl --fail-with-body -sS \
    -o "$response" -w '%{http_code}' \
    "https://ghcr.io/token?scope=repository:bocklabs/${app}:pull")"
  CURL_STATUS=$?
  set -e
  if [ "${CURL_STATUS}" -eq 0 ]; then
    jq -er .token "$response"
    return
  fi
  if [ "${TOKEN_STATUS}" = "403" ] && jq -e '(.errors // []) | any(.code == "DENIED")' "$response" > /dev/null; then
    return 0
  fi
  echo "FATAL: GHCR token request failed (${TOKEN_STATUS:-network error})" >&2
  return 1
}

ghcr_require_pull_token() {
  local token
  token="$(ghcr_pull_token "$1" "$2")" || return
  if [ -z "$token" ]; then
    echo "FATAL: GHCR package is not readable" >&2
    return 1
  fi
  printf '%s\n' "$token"
}
