#!/usr/bin/env bash
# Shared registry helpers for local composite actions.

is_dockerhub_ref() {
  [[ "$1" == docker.io/* ]]
}

set_skopeo_credentials() {
  local ref="$1" flag="${2:---src-creds}"
  SKOPEO_CREDS=()
  if is_dockerhub_ref "$ref"; then
    SKOPEO_CREDS=("$flag" "${DOCKERHUB_USERNAME}:${DOCKERHUB_TOKEN}")
  fi
}

run_skopeo() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/workspace "$@"
}

copy_source_oci() {
  set_skopeo_credentials "$1"
  run_skopeo "${SKOPEO_IMAGE}" \
    copy --retry-times 3 --preserve-digests --remove-signatures ${SKOPEO_CREDS[@]+"${SKOPEO_CREDS[@]}"} \
    "docker://${1}@${2}" "oci:/workspace/${3}"
}
