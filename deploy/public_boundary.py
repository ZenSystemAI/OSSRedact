#!/usr/bin/env python3
"""Fail closed on paths that must not cross the public repository boundary."""
from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import re
import sys


_STRESS_ORGADDR_HELDOUT = "validation/stress_orgaddr_heldout.jsonl"
_PRIVATE_EXTENSION_MODEL_SENTINEL = "extension/public/model/.gitkeep"
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

_PUBLIC_ONLY_PLANNING_SEGMENTS = frozenset({"plans"})
_COMMON_AGENT_STATE_SEGMENTS = frozenset({".agents"})
_SUPPORTED_PROFILES = frozenset({"public", "private"})
_ARCHIVE_COMPRESSION_WRAPPER_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tar.lzma",
    ".tar.lz",
    ".tar",
    ".tgz",
    ".tbz2",
    ".tbz",
    ".txz",
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".lzma",
    ".lz",
)
_BACKUP_WRAPPER_SUFFIXES = (".backup", ".bak", ".orig", ".old", ".save", "~")
_TRANSFORM_WRAPPER_SUFFIXES = (
    _ARCHIVE_COMPRESSION_WRAPPER_SUFFIXES + _BACKUP_WRAPPER_SUFFIXES
)
_ANNOTATION_PROSE_VERSION_SUFFIX = re.compile(
    r"^(?P<prefix>.+)-v[0-9]+$", re.IGNORECASE
)
_MACHINE_PINNED_GPU_ARTIFACT_FILENAME = re.compile(
    r"^(?:ossredact-gate-gpu-.+\.service|requirements-gate-gpu-.+\.lock)$"
)

_ANNOTATION_TRAILING_PUNCTUATION = ".,;:!?"
_ANNOTATION_PROSE_SUFFIX_DELIMITERS = "#@"
_ANNOTATION_PATH_TOKEN_CHARACTERS = r"A-Za-z0-9_./+@=~$%&#\\-"
_ANNOTATION_PATH_CANDIDATE = re.compile(
    rf"""
    (?<![{_ANNOTATION_PATH_TOKEN_CHARACTERS}])
    (?P<path>[{_ANNOTATION_PATH_TOKEN_CHARACTERS}]+)
    (?![{_ANNOTATION_PATH_TOKEN_CHARACTERS}])
    """,
    re.VERBOSE,
)
_ANNOTATION_STANDALONE_PATH = re.compile(
    r"""
    (?:
        AGENTS\.md
        | PRIOR-ART\.md
        | gateway-config\.yaml
        | [A-Za-z0-9_.+@=~$%&#-]*prelaunch-audit[A-Za-z0-9_.+@=~$%&#-]*
        | [A-Za-z0-9_.+@=~$%&#-]*\.pii\.(?:json|txt)
        | [A-Za-z0-9_.+@=~$%&#-]*\.jsonl
        | ossredact-gate-gpu-[A-Za-z0-9_.+@=~$%&#-]+\.service
        | requirements-gate-gpu-[A-Za-z0-9_.+@=~$%&#-]+\.lock
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_MODEL_SEGMENTS = frozenset(
    {
        "datasets",
        "models",
        "model",
        "out",
        ".ovcache",
        "model-v11r5-base-int8",
    }
)
_RUNTIME_SEGMENTS = frozenset(
    {
        "expenses-eval",
        "output-data",
        "maps",
        "private",
        ".claude",
        ".playwright",
        ".playwright-mcp",
    }
)


@dataclass(frozen=True)
class Violation:
    """A rejected repository path and the policy category that rejected it."""

    path: str
    category: str


def _relative_posix_segments(path: str) -> tuple[str, ...] | None:
    """Return canonical relative POSIX path segments, or ``None`` if malformed."""
    if not isinstance(path, str) or not path or path.startswith("/"):
        return None
    if "\\" in path:
        return None
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in path
    ):
        return None

    segments = tuple(path.split("/"))
    if any(not segment or segment in {".", ".."} for segment in segments):
        return None
    if _WINDOWS_DRIVE.match(segments[0]):
        return None
    return segments


def _contains_subpath(
    segments: tuple[str, ...], expected: tuple[str, ...]
) -> bool:
    width = len(expected)
    return any(segments[index : index + width] == expected for index in range(len(segments)))

def _strip_transform_wrappers(
    segment: str, suffixes: tuple[str, ...] = _TRANSFORM_WRAPPER_SUFFIXES
) -> str:
    """Recursively remove recognized archive, compression, and backup wrappers."""
    unwrapped = segment
    while unwrapped:
        folded = unwrapped.casefold()
        suffix = next(
            (
                candidate
                for candidate in suffixes
                if len(unwrapped) > len(candidate) and folded.endswith(candidate)
            ),
            None,
        )
        if suffix is None:
            break
        unwrapped = unwrapped[: -len(suffix)]
    return unwrapped


def _transformed_path(segments: tuple[str, ...]) -> str | None:
    """Return a wrapper-free path when any segment carries a known wrapper."""
    transformed = tuple(_strip_transform_wrappers(segment) for segment in segments)
    if transformed == segments:
        return None
    return "/".join(transformed)


def _has_archive_or_compression_wrapper(path: str) -> bool:
    """Return whether a prose filename carries an archive/compression wrapper."""
    return any(
        _strip_transform_wrappers(segment, _ARCHIVE_COMPRESSION_WRAPPER_SUFFIXES)
        != segment
        for segment in path.split("/")
    )


def _validated_profile(profile: str) -> str:
    if not isinstance(profile, str) or profile not in _SUPPORTED_PROFILES:
        raise ValueError("unsupported repository boundary profile")
    return profile


def _common_agent_state_category(folded: tuple[str, ...]) -> str | None:
    if any(segment in _COMMON_AGENT_STATE_SEGMENTS for segment in folded):
        return "internal-planning"
    return None


def _public_only_category(folded: tuple[str, ...]) -> str | None:
    if any(
        _MACHINE_PINNED_GPU_ARTIFACT_FILENAME.fullmatch(segment)
        for segment in folded
    ):
        return "machine-pinned-artifact"
    if any(segment in _PUBLIC_ONLY_PLANNING_SEGMENTS for segment in folded):
        return "internal-planning"
    if "agents.md" in folded:
        return "agent-instructions"
    if "prior-art.md" in folded:
        return "internal-research"
    if any("prelaunch-audit" in segment for segment in folded):
        return "prelaunch-audit"
    if _contains_subpath(folded, ("docs", "superpowers")):
        return "internal-planning"
    if _contains_subpath(folded, ("docs", "research")):
        return "internal-research"
    if "extension" in folded:
        return "unreleased-extension"
    return None


def _common_sensitive_category(path: str, folded: tuple[str, ...]) -> str | None:
    if any(segment in _MODEL_SEGMENTS for segment in folded):
        return "training-data-or-model"
    if any(segment.startswith("model.bak-") for segment in folded):
        return "model-backup"
    if any(".bak" in segment for segment in folded):
        return "backup-artifact"

    if _contains_subpath(folded, ("validation", "realworld")):
        return "real-world-validation"
    if any(segment in _RUNTIME_SEGMENTS for segment in folded):
        return "private-runtime-data"
    if any(
        segment.endswith(".pii.json") or segment.endswith(".pii.txt")
        for segment in folded
    ):
        return "pii-artifact"
    if "gateway-config.yaml" in folded:
        return "host-configuration"

    if any(segment.endswith(".jsonl") for segment in folded):
        if path != _STRESS_ORGADDR_HELDOUT:
            return "jsonl-corpus"

    return None


def _classify_path(
    path: str, profile: str, *, original_path: str | None = None
) -> str | None:
    source_path = path if original_path is None else original_path
    segments = _relative_posix_segments(path)
    if segments is None:
        return "invalid-path"

    folded = tuple(segment.casefold() for segment in segments)

    common_agent_state = _common_agent_state_category(folded)
    if common_agent_state is not None:
        return common_agent_state

    if profile == "public":
        public_only = _public_only_category(folded)
        if public_only is not None:
            return public_only

    if profile == "private" and source_path == _PRIVATE_EXTENSION_MODEL_SENTINEL:
        return None

    common_sensitive = _common_sensitive_category(source_path, folded)
    if common_sensitive is not None:
        return common_sensitive

    transformed_path = _transformed_path(segments)
    if transformed_path is None:
        return None
    return _classify_path(
        transformed_path, profile, original_path=source_path
    )


def classify_path(path: str, *, profile: str = "public") -> str | None:
    """Return the selected boundary category that rejects ``path``, if any."""
    return _classify_path(path, _validated_profile(profile))


def violations(
    paths: Iterable[str], *, profile: str = "public"
) -> list[Violation]:
    """Return rejected paths in input order without deduplicating them."""
    validated_profile = _validated_profile(profile)
    found: list[Violation] = []
    for path in paths:
        category = _classify_path(path, validated_profile)
        if category is not None:
            found.append(Violation(path=path, category=category))
    return found


def _strip_annotation_trailing_punctuation(source: str) -> str:
    """Strip sentence punctuation without normalizing terminal dot segments."""
    path = source
    while path and path[-1] in _ANNOTATION_TRAILING_PUNCTUATION:
        if path.endswith("/.") or path.endswith("/.."):
            break
        path = path[:-1]
    return path

def _annotation_url_path(path: str) -> str | None:
    """Return the path after a scheme-relative URL authority, if present."""
    authority_end = path.find("/", 2)
    if authority_end < 0:
        return None
    return path[authority_end + 1 :]


def _annotation_path_candidate(path: str, source: str) -> bool:
    """Return whether a prose token has an explicit repository-path shape."""
    if "/" in source or "\\" in source:
        return bool(path) and not source.startswith("//")
    return (
        _ANNOTATION_STANDALONE_PATH.fullmatch(path) is not None
        or _has_archive_or_compression_wrapper(path)
    )


def _annotation_suffix_candidate(
    path: str, source: str, profile: str
) -> tuple[str, str] | None:
    """Return a sensitive repository path before a tested prose suffix."""
    prefixes: list[str] = []
    for delimiter_index in range(len(path) - 1, -1, -1):
        if path[delimiter_index] in _ANNOTATION_PROSE_SUFFIX_DELIMITERS:
            prefixes.append(path[:delimiter_index])
    if path.casefold().endswith(".bak"):
        prefixes.append(path[:-4])
    version_match = _ANNOTATION_PROSE_VERSION_SUFFIX.fullmatch(path)
    if version_match is not None:
        prefixes.append(version_match.group("prefix"))

    for prefix in prefixes:
        if not _annotation_path_candidate(prefix, prefix):
            continue
        category = _classify_path(prefix, profile)
        if category is not None:
            return prefix, category
    return None


def annotation_violations(
    text: str, *, profile: str = "public"
) -> list[Violation]:
    """Return policy violations found in path-like release annotation text."""
    validated_profile = _validated_profile(profile)
    if not isinstance(text, str):
        raise TypeError("annotation text must be a string")

    found: list[Violation] = []
    for match in _ANNOTATION_PATH_CANDIDATE.finditer(text):
        source = match.group("path")
        path = _strip_annotation_trailing_punctuation(source)
        if not path:
            continue
        if path.startswith("//"):
            url_path = _annotation_url_path(path)
            if not url_path:
                continue
            path = url_path
            source = url_path
        if _annotation_path_candidate(path, source):
            category = _classify_path(path, validated_profile)
            if category is not None:
                found.append(Violation(path=path, category=category))
            continue

        suffix_candidate = _annotation_suffix_candidate(
            path, source, validated_profile
        )
        if suffix_candidate is not None:
            canonical_path, category = suffix_candidate
            found.append(Violation(path=canonical_path, category=category))
    return found


def _read_stdin0() -> list[str]:
    """Read zero or more NUL-terminated path fields from standard input."""
    payload = sys.stdin.buffer.read()
    if not payload:
        return []

    if payload.endswith(b"\0"):
        fields = payload[:-1].split(b"\0")
    else:
        fields = payload.split(b"\0")
    return [field.decode("utf-8", errors="surrogateescape") for field in fields]


def _escaped_path(path: str) -> str:
    """Render a path without allowing terminal control characters into diagnostics."""
    return path.encode("unicode_escape", errors="backslashreplace").decode("ascii")


def _stdin0_main(profile: str) -> int:
    found = violations(_read_stdin0(), profile=profile)
    for violation in found:
        print(
            f"public boundary rejected [{violation.category}]: "
            f"{_escaped_path(violation.path)}",
            file=sys.stderr,
        )
    return 1 if found else 0


def _text_main(profile: str) -> int:
    """Validate UTF-8 release annotation text without echoing candidate values."""
    try:
        text = sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        print("public boundary rejected [invalid-text-encoding]", file=sys.stderr)
        return 1

    found = annotation_violations(text, profile=profile)
    for violation in found:
        print(f"public boundary rejected [{violation.category}]", file=sys.stderr)
    return 1 if found else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    input_mode = parser.add_mutually_exclusive_group(required=True)
    input_mode.add_argument(
        "--stdin0",
        action="store_true",
        help="read NUL-delimited repository-relative paths from standard input",
    )
    input_mode.add_argument(
        "--text",
        action="store_true",
        help="read UTF-8 release annotation text from standard input",
    )
    parser.add_argument(
        "--profile",
        choices=("public", "private"),
        default="public",
        help="repository boundary profile to enforce",
    )
    arguments = parser.parse_args(argv)
    if arguments.stdin0:
        return _stdin0_main(arguments.profile)
    return _text_main(arguments.profile)


if __name__ == "__main__":
    raise SystemExit(main())
