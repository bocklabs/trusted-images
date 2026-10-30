"""Compare validated Alpine versions with apk-tools version semantics."""

from __future__ import annotations

import re
from functools import total_ordering

_VERSION = re.compile(
    r"([0-9]+)((?:\.[0-9]+)*)([a-z]?)"
    r"((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*)"
    r"(?:~([0-9a-f]+))?(?:-r([0-9]+))?"
)
_SUFFIX = re.compile(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)([0-9]*)")
_INITIAL, _DIGIT, _LETTER, _SUFFIX_KIND, _SUFFIX_NO, _HASH, _REVISION, _END = range(8)
_SUFFIX_ORDER = {name: index for index, name in enumerate(
    ("alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p")
)}


def _number(value: str) -> int:
    # Match APK unsigned 64-bit overflow when accumulating numeric tokens.
    number = 0
    for char in value:
        number = (number * 10 + ord(char) - ord("0")) & ((1 << 64) - 1)
    return number


def _tokens(value: str) -> list[tuple[int, str]]:
    match = _VERSION.fullmatch(value)
    if not match:
        raise ValueError(f"invalid Alpine version: {value}")
    initial, dots, letter, suffixes, commit_hash, revision = match.groups()
    tokens = [(_INITIAL, initial)]
    tokens.extend((_DIGIT, part) for part in dots.split(".") if part)
    if letter:
        tokens.append((_LETTER, letter))
    for suffix in _SUFFIX.finditer(suffixes):
        tokens.append((_SUFFIX_KIND, suffix[1]))
        if suffix[2]:
            tokens.append((_SUFFIX_NO, suffix[2]))
    if commit_hash is not None:
        tokens.append((_HASH, commit_hash))
    if revision is not None:
        tokens.append((_REVISION, revision))
    tokens.append((_END, ""))
    return tokens


def _kind_compare(left_kind: int, left: str, right_kind: int, right: str) -> int:
    if left_kind == _SUFFIX_KIND and _SUFFIX_ORDER[left] < _SUFFIX_ORDER[""]:
        return -1
    if right_kind == _SUFFIX_KIND and _SUFFIX_ORDER[right] < _SUFFIX_ORDER[""]:
        return 1
    return (right_kind > left_kind) - (right_kind < left_kind)


def _value_compare(kind: int, left: str, right: str) -> int:
    if kind == _SUFFIX_KIND:
        left_value, right_value = _SUFFIX_ORDER[left], _SUFFIX_ORDER[right]
    elif kind in (_INITIAL, _DIGIT, _SUFFIX_NO, _REVISION) and not (
        kind == _DIGIT and (left.startswith("0") or right.startswith("0"))
    ):
        left_value, right_value = _number(left), _number(right)
    else:
        return (left > right) - (left < right)
    return (left_value > right_value) - (left_value < right_value)


@total_ordering
class AlpineVersion:
    def __init__(self, version: str):
        self.tokens = _tokens(version)

    def _compare(self, other: AlpineVersion) -> int:
        for (left_kind, left), (right_kind, right) in zip(self.tokens, other.tokens):
            if left_kind != right_kind:
                return _kind_compare(left_kind, left, right_kind, right)
            if left_kind == _END:
                return 0
            result = _value_compare(left_kind, left, right)
            if result:
                return result
        raise AssertionError("Alpine version tokens have no end")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AlpineVersion):
            return NotImplemented
        return self._compare(other) == 0

    def __lt__(self, other: AlpineVersion) -> bool:
        if not isinstance(other, AlpineVersion):
            return NotImplemented
        return self._compare(other) < 0
