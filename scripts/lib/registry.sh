#!/usr/bin/env bash
# Shared registry helpers for local composite actions.

is_dockerhub_ref() {
  [[ "$1" == docker.io/* ]]
}

set_skopeo_auth() {
  local ref="$1" flag="${2:---src-authfile}" auth
  SKOPEO_AUTH=()
  SKOPEO_AUTHFILE=""
  is_dockerhub_ref "$ref" || return 0
  auth="$(printf '%s:%s' "${DOCKERHUB_USERNAME}" "${DOCKERHUB_TOKEN}" | base64 -w0)"
  SKOPEO_AUTHFILE="$(mktemp "${RUNNER_TEMP:-/tmp}/skopeo-auth.XXXXXX")"
  trap 'rm -f "${SKOPEO_AUTHFILE:-}"' EXIT
  printf '{"auths":{"docker.io":{"auth":"%s"}}}\n' "${auth}" > "${SKOPEO_AUTHFILE}"
  chmod 600 "${SKOPEO_AUTHFILE}"
  SKOPEO_AUTH=("$flag" /run/skopeo-auth.json)
}

run_skopeo() {
  local auth_mount=()
  [ -z "${SKOPEO_AUTHFILE:-}" ] || auth_mount=(-v "${SKOPEO_AUTHFILE}:/run/skopeo-auth.json:ro")
  docker run --rm --user "$(id -u):$(id -g)" ${auth_mount[@]+"${auth_mount[@]}"} \
    -v "$PWD":/workspace "$@"
}

copy_source_oci() {
  [ -n "${1:-}" ] && [ -n "${2:-}" ] && [ -n "${3:-}" ] || {
    echo "FATAL: source OCI copy requires ref, digest, and target" >&2
    return 1
  }
  [ -n "${SKOPEO_IMAGE:-}" ] || { echo "FATAL: Skopeo image is empty" >&2; return 1; }
  set_skopeo_auth "$1"
  run_skopeo "${SKOPEO_IMAGE}" \
    copy --retry-times 3 --preserve-digests --remove-signatures ${SKOPEO_AUTH[@]+"${SKOPEO_AUTH[@]}"} \
    "docker://${1}@${2}" "oci:/workspace/${3}"
}
