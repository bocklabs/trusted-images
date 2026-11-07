"""Bind a Docker archive's selected config bytes to an OCI manifest."""

import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import IO


def archive_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> IO[bytes]:
    if not member.isfile():
        raise ValueError("archive config and manifest must be regular files")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("cannot read archive member")
    return stream


def archive_config(source: IO[bytes], names: set[str], size: int) -> tuple[object, dict[str, str]]:
    found: dict[str, str] = {}
    selected = None
    manifest_seen = False
    with tarfile.open(fileobj=source, mode="r|*") as archive:
        for member in archive:
            if member.name == "manifest.json":
                if manifest_seen or member.size > 4 * 1024 * 1024:
                    raise ValueError("duplicate or oversized archive manifest")
                manifest_seen = True
                selected = json.load(archive_member(archive, member))
            elif member.name in names:
                if member.name in found or member.size != size:
                    raise ValueError("duplicate archive config or config size mismatch")
                checksum = hashlib.sha256()
                stream = archive_member(archive, member)
                while chunk := stream.read(1024 * 1024):
                    checksum.update(chunk)
                found[member.name] = "sha256:" + checksum.hexdigest()
    return selected, found


def drain(source: IO[bytes], primary_error: BaseException | None) -> None:
    try:
        while source.read(1024 * 1024):
            pass
    except OSError as drain_error:
        if primary_error is None:
            raise
        primary_error.add_note(f"archive stream drain failed: {drain_error}")


def verify(manifest_path: Path, source: IO[bytes]) -> None:
    verified = False
    try:
        manifest = json.loads(manifest_path.read_bytes())
        config = manifest.get("config") if isinstance(manifest, dict) else None
        digest = config.get("digest") if isinstance(config, dict) else None
        size = config.get("size") if isinstance(config, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid OCI config digest")
        if type(size) is not int or size <= 0:
            raise ValueError("invalid OCI config size")
        names = {digest[7:] + ".json", "blobs/sha256/" + digest[7:]}
        selected, found = archive_config(source, names, size)
        if not isinstance(selected, list) or len(selected) != 1 or not isinstance(selected[0], dict):
            raise ValueError("archive must select exactly one image")
        config_path = selected[0].get("Config")
        if not isinstance(config_path, str) or found.get(config_path) != digest:
            raise ValueError("selected archive config digest mismatch")
        verified = True
    finally:
        drain(source, None if verified else sys.exception())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_candidate_archive.py OCI_MANIFEST ARCHIVE|-")
    try:
        if sys.argv[2] == "-":
            verify(Path(sys.argv[1]), sys.stdin.buffer)
        else:
            with open(sys.argv[2], "rb") as stream:
                verify(Path(sys.argv[1]), stream)
    except (OSError, TypeError, ValueError, tarfile.TarError) as exc:
        raise SystemExit(f"FATAL: candidate archive config binding failed: {exc}") from exc
