#!/usr/bin/env bash
# Shared OCI helpers for local composite actions.

source "$(dirname "${BASH_SOURCE[0]}")/registry.sh"

load_oci_archive() {
  local skopeo="$1" archive="$2" target="$3"
  run_skopeo "$skopeo" \
    copy --preserve-digests \
    oci:/workspace/candidate-oci:candidate \
    "docker-archive:/workspace/${archive}:${target}"
  docker load --input "$archive" || return
  local image_id
  image_id="$(docker image inspect "$target" --format '{{.Id}}')" || return
  [ -n "${image_id}" ] || { echo "FATAL: loaded image has no ID" >&2; return 1; }
  printf '%s\n' "${image_id}"
}
