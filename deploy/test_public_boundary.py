"""Public-boundary policy contract tests.

These tests use synthetic path strings only and never invoke ``git push``.  They
specify the canonical helper interface expected at ``deploy/public_boundary.py``:

* ``classify_path(path: str, *, profile: str) -> str | None`` returns a
  canonical policy category for a rejected repository-relative path, otherwise
  ``None``.
* ``violations(paths, *, profile: str) -> list[Violation]`` preserves input
  order and exposes immutable ``Violation(path, category)`` records.
* ``annotation_violations(text: str, *, profile: str) -> list[Violation]``
  applies those same canonical categories to path-like tokens in release
  annotation text.
* ``python deploy/public_boundary.py --stdin0`` consumes NUL-delimited paths;
  mutually exclusive ``--text`` consumes UTF-8 annotation text.
"""
from __future__ import annotations

import dataclasses
import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "public_boundary.py"
INSTALLER = ROOT / "deploy" / "install-git-hooks.sh"
GUARD = ROOT / "deploy" / "pre-push-guard.sh"

# Make the repository's namespace package win even when pytest is invoked from
# outside the repository root.
sys.path.insert(0, str(ROOT))
public_boundary = importlib.import_module("deploy.public_boundary")


def _assert_rejected(path: str) -> None:
    category = public_boundary.classify_path(path)
    assert isinstance(category, str) and category.strip(), (
        f"expected {path!r} to be rejected with a nonempty category, got {category!r}"
    )


def _run_cli(stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(HELPER), "--stdin0"],
        cwd=ROOT,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

def _run_text_cli(text: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(HELPER), "--text", "--profile", "public"],
        cwd=ROOT,
        input=text.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


@pytest.mark.parametrize(
    "path",
    (
        "",
        "/absolute/private.txt",
        "../outside-repository.txt",
        "src/../../outside-repository.txt",
        r"src\\windows-separator.py",
        r"plans\release-checklist.md",
        "C:/drive-rooted.txt",
        ".",
        "src/contains\x00nul.py",
        "src/contains\nnewline.py",
    ),
    ids=(
        "empty",
        "absolute",
        "parent-traversal",
        "embedded-traversal",
        "windows-separator",
        "windows-repository-token",
        "drive-rooted",
        "repository-root",
        "nul",
        "newline",
    ),
)
def test_classify_path_rejects_empty_absolute_traversal_and_malformed_names(path: str):
    assert public_boundary.classify_path(path) == "invalid-path"


@pytest.mark.parametrize(
    "path",
    (
        "plans/release-checklist.md",
        "AGENTS.md",
        "workbench/AGENTS.md",
        ".agents/worker-state.json",
        "extension/src/background.ts",
        "release/PRELAUNCH-AUDIT-findings.md",
        "docs/superpowers/specs/internal-policy.md",
        "docs/research/source-notes.md",
        "PRIOR-ART.md",
        "datasets/synthetic/train.csv",
        "models/private-model.safetensors",
        "model/host-only-weights.bin",
        "out/checkpoint.bin",
        "model.bak-20260709/checkpoint.bin",
        "artifacts/checkpoint.bak-20260709",
        ".ovcache/compiled-model.blob",
        "validation/realworld/receipt.txt",
        "expenses-eval/expense.txt",
        "output-data/customer-record.txt",
        "scratch/customer.pii.json",
        "scratch/customer.pii.txt",
        "maps/encrypted-entity-map.bin",
        "private/runtime-state.json",
        "gateway-config.yaml",
        ".claude/settings.json",
        ".playwright/session.json",
        ".playwright-mcp/session.json",
    ),
    ids=(
        "plans",
        "agents-root",
        "agents-nested",
        "agent-scratch",
        "extension",
        "prelaunch-audit",
        "internal-specs",
        "internal-research",
        "prior-art",
        "datasets",
        "models",
        "singular-model",
        "training-output",
        "model-backup-directory",
        "backup-artifact",
        "model-cache",
        "realworld-validation",
        "expenses",
        "output-data",
        "pii-json",
        "pii-text",
        "maps",
        "private-runtime",
        "gateway-config",
        "local-claude",
        "local-playwright",
        "local-playwright-mcp",
    ),
)
def test_classify_path_rejects_every_sensitive_public_boundary_category(path: str):
    _assert_rejected(path)


@pytest.mark.parametrize(
    "path",
    (
        "src/public_api.py",
        "packages/redaction-core/src/public_api.ts",
        "deploy/requirements-gate-cpu.lock",
        "deploy/systemd/user/ossredact-gate-cpu.service",
        "deploy/systemd/user/ossredact-egress.service",
        "validation/parity_vectors.json",
        "validation/stress_orgaddr_heldout.jsonl",
    ),
    ids=(
        "ordinary-public-source",
        "ordinary-public-typescript",
        "cpu-lock",
        "desktop-cpu-user-unit",
        "desktop-egress-user-unit",
        "parity-vectors",
        "exact-stress-jsonl",
    ),
)
def test_classify_path_allows_approved_public_artifacts(path: str):
    assert public_boundary.classify_path(path) is None


@pytest.mark.parametrize(
    "path",
    (
        "fixtures/ordinary.jsonl",
        "validation/not-the-approved-stress-fixture.jsonl",
        "validation/stress_orgaddr_heldout-copy.jsonl",
        "validation/STRESS_ORGADDR_HELDOUT.jsonl",
    ),
    ids=("generic-jsonl", "other-validation-jsonl", "stress-near-match", "stress-case-variant"),
)
def test_classify_path_rejects_every_non_allowlisted_jsonl(path: str):
    _assert_rejected(path)


@pytest.mark.parametrize(
    "path",
    (
        "plans/validation/stress_orgaddr_heldout.jsonl",
        "validation/realworld/stress_orgaddr_heldout.jsonl",
        "output-data/stress_orgaddr_heldout.jsonl",
    ),
    ids=("plans-prefix", "realworld-prefix", "output-data-prefix"),
)
def test_sensitive_path_denies_take_precedence_over_stress_fixture_suffix(path: str):
    """Only the one canonical relative stress path may bypass the JSONL deny rule."""
    _assert_rejected(path)


def test_violations_returns_ordered_immutable_records_for_only_rejected_paths():
    paths = (
        "src/public_api.py",
        "plans/internal-plan.md",
        "validation/stress_orgaddr_heldout.jsonl",
        "validation/realworld/stress_orgaddr_heldout.jsonl",
        "fixtures/ordinary.jsonl",
        "plans/internal-plan.md",
    )

    found = public_boundary.violations(iter(paths))

    assert isinstance(found, list)
    assert [violation.path for violation in found] == [
        "plans/internal-plan.md",
        "validation/realworld/stress_orgaddr_heldout.jsonl",
        "fixtures/ordinary.jsonl",
        "plans/internal-plan.md",
    ]
    assert all(isinstance(violation, public_boundary.Violation) for violation in found)
    assert all(
        isinstance(violation.category, str) and violation.category.strip()
        for violation in found
    )

    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        found[0].path = "rewritten-path"


def test_violations_returns_an_empty_list_when_every_path_is_allowed():
    found = public_boundary.violations(
        (
            "src/public_api.py",
            "deploy/requirements-gate-cpu.lock",
            "validation/stress_orgaddr_heldout.jsonl",
        )
    )

    assert found == []


def test_stdin0_cli_succeeds_for_nul_delimited_allowed_paths():
    completed = _run_cli(
        b"src/public_api.py\0"
        b"deploy/requirements-gate-cpu.lock\0"
        b"deploy/systemd/user/ossredact-gate-cpu.service\0"
        b"validation/parity_vectors.json\0"
        b"validation/stress_orgaddr_heldout.jsonl\0"
    )

    assert completed.returncode == 0, (
        completed.stdout.decode("utf-8", errors="backslashreplace"),
        completed.stderr.decode("utf-8", errors="backslashreplace"),
    )


def test_stdin0_cli_rejects_an_explicit_empty_path_field():
    completed = _run_cli(b"\0src/public_api.py\0")

    assert completed.returncode != 0


def test_stdin0_cli_rejects_and_escapes_control_characters_in_diagnostics():
    malicious_path = "plans/unsafe\ncontinuation\x1b[2J.md"
    completed = _run_cli(
        b"src/public_api.py\0"
        + malicious_path.encode("utf-8")
        + b"\0validation/stress_orgaddr_heldout.jsonl\0"
    )
    diagnostics = (completed.stdout + completed.stderr).decode(
        "utf-8", errors="backslashreplace"
    )

    assert completed.returncode != 0
    assert "plans/unsafe" in diagnostics
    assert malicious_path not in diagnostics
    assert "\x1b" not in diagnostics
    assert re.search(r"\\(?:n|x0a|u000a)", diagnostics, flags=re.IGNORECASE)
    assert re.search(r"\\(?:x1b|u001b|033)", diagnostics, flags=re.IGNORECASE)

PUBLIC_ANNOTATION_FORBIDDEN_CASES = (
    (
        "Release notes cite PRIOR-ART.md before publication",
        "PRIOR-ART.md",
        "PRIOR-ART.md",
        "internal-research",
    ),
    (
        "Release notes cite docs/research/source-notes.md before publication",
        "docs/research/source-notes.md",
        "docs/research/source-notes.md",
        "internal-research",
    ),
    (
        "Release notes cite plans/release-checklist.md before publication",
        "plans/release-checklist.md",
        "plans/release-checklist.md",
        "internal-planning",
    ),
    (
        "Release notes cite https://docs.example.test/plans/release-checklist.md before publication",
        "https://docs.example.test/plans/release-checklist.md",
        "plans/release-checklist.md",
        "internal-planning",
    ),
    (
        "Release notes cite https://docs.example.test/extension/src/background.ts before publication",
        "https://docs.example.test/extension/src/background.ts",
        "extension/src/background.ts",
        "unreleased-extension",
    ),
    (
        "Release notes cite AGENTS.md before publication",
        "AGENTS.md",
        "AGENTS.md",
        "agent-instructions",
    ),
    (
        "Release notes cite extension/src/background.ts before publication",
        "extension/src/background.ts",
        "extension/src/background.ts",
        "unreleased-extension",
    ),
    (
        "Release notes cite deploy/systemd/user/ossredact-gate-gpu-synthetic-host.service",
        "deploy/systemd/user/ossredact-gate-gpu-synthetic-host.service",
        "deploy/systemd/user/ossredact-gate-gpu-synthetic-host.service",
        "machine-pinned-artifact",
    ),
    (
        "Release notes cite deploy/ossredact-gate-gpu-lab+host.service",
        "deploy/ossredact-gate-gpu-lab+host.service",
        "deploy/ossredact-gate-gpu-lab+host.service",
        "machine-pinned-artifact",
    ),
    (
        "Release notes cite train.jsonl#note before publication",
        "train.jsonl#note",
        "train.jsonl",
        "jsonl-corpus",
    ),
    (
        "Release notes cite customer.pii.json@v2 before publication",
        "customer.pii.json@v2",
        "customer.pii.json",
        "pii-artifact",
    ),
    (
        "Release notes cite customer.pii.json-v2 before publication",
        "customer.pii.json-v2",
        "customer.pii.json",
        "pii-artifact",
    ),
    (
        "Release notes cite train.jsonl.bak before publication",
        "train.jsonl.bak",
        "train.jsonl",
        "jsonl-corpus",
    ),
    (
        "Release notes cite AGENTS.md.bak before publication",
        "AGENTS.md.bak",
        "AGENTS.md",
        "agent-instructions",
    ),
)


@pytest.mark.parametrize(
    ("text", "candidate", "forbidden_path", "category"),
    PUBLIC_ANNOTATION_FORBIDDEN_CASES,
    ids=(
        "prior-art",
        "research-notes",
        "planning",
        "https-planning",
        "https-extension",
        "agent-instructions",
        "extension",
        "host-suffixed-gpu-unit",
        "plus-suffixed-gpu-unit",
        "jsonl-prose-suffix",
        "pii-json-prose-suffix",
        "pii-json-version-suffix",
        "jsonl-backup-suffix",
        "agent-instructions-backup-suffix",
    ),
)
def test_annotation_violations_reuses_canonical_categories_for_public_prose(
    text: str, candidate: str, forbidden_path: str, category: str
):
    assert public_boundary.annotation_violations(text, profile="public") == [
        public_boundary.Violation(path=forbidden_path, category=category)
    ]


def test_annotation_violations_allows_ordinary_release_prose_with_generic_gpu_unit():
    text = (
        "Release notes: gate/gate_service_gpu.py now supports "
        "deploy/systemd/user/ossredact-gate-gpu.service"
    )

    assert public_boundary.annotation_violations(text, profile="public") == []

def test_annotation_violations_and_text_cli_allow_ordinary_release_prose():
    """Path-token hardening must not reject ordinary discussion of review work."""
    text = (
        "The release notes summarize customer records, training examples, "
        "backup procedures, and agent roles."
    )

    assert public_boundary.annotation_violations(text, profile="public") == []

    completed = _run_text_cli(text)

    assert completed.returncode == 0, (
        completed.stdout.decode("utf-8", errors="backslashreplace"),
        completed.stderr.decode("utf-8", errors="backslashreplace"),
    )


@pytest.mark.parametrize(
    ("text", "candidate", "category"),
    tuple(
        (text, candidate, category)
        for text, candidate, _, category in PUBLIC_ANNOTATION_FORBIDDEN_CASES
    ),
    ids=(
        "prior-art",
        "research-notes",
        "planning",
        "https-planning",
        "https-extension",
        "agent-instructions",
        "extension",
        "host-suffixed-gpu-unit",
        "plus-suffixed-gpu-unit",
        "jsonl-prose-suffix",
        "pii-json-prose-suffix",
        "pii-json-version-suffix",
        "jsonl-backup-suffix",
        "agent-instructions-backup-suffix",
    ),
)
def test_text_cli_rejects_public_annotation_tokens_without_echoing_them(
    text: str, candidate: str, category: str
):
    completed = _run_text_cli(text)
    diagnostics = (completed.stdout + completed.stderr).decode(
        "utf-8", errors="backslashreplace"
    )

    assert completed.returncode == 1
    assert f"[{category}]" in diagnostics
    assert candidate not in diagnostics


def test_text_cli_allows_ordinary_release_prose_with_generic_gpu_unit():
    text = (
        "Release notes: gate/gate_service_gpu.py now supports "
        "deploy/systemd/user/ossredact-gate-gpu.service"
    )
    completed = _run_text_cli(text)

    assert completed.returncode == 0, (
        completed.stdout.decode("utf-8", errors="backslashreplace"),
        completed.stderr.decode("utf-8", errors="backslashreplace"),
    )


@pytest.mark.parametrize(
    "candidate",
    (
        "./plans/release-checklist.md",
        "plans/./release-checklist.md",
        "../plans/release-checklist.md",
        r"plans\release-checklist.md",
        r"plans\\release-checklist.md",
    ),
    ids=(
        "leading-current-directory",
        "embedded-current-directory",
        "parent-directory",
        "windows-single-backslash",
        "windows-repeated-backslash",
    ),
)
def test_annotation_paths_fail_closed_for_malformed_repository_like_tokens(
    candidate: str,
):
    """Release annotation text may not normalize malformed repository paths."""
    text = f"Synthetic release notes cite {candidate}"

    assert public_boundary.annotation_violations(text, profile="public") == [
        public_boundary.Violation(path=candidate, category="invalid-path")
    ]

    completed = _run_text_cli(text)
    diagnostics = (completed.stdout + completed.stderr).decode(
        "utf-8", errors="backslashreplace"
    )

    assert completed.returncode == 1
    assert candidate not in diagnostics


def test_annotation_text_allows_an_ordinary_https_url_in_release_prose():
    """URLs are prose, not repository-relative artifact references."""
    text = "Read the public release notes at https://docs.example.test/releases/2026-07."

    assert public_boundary.annotation_violations(text, profile="public") == []

    completed = _run_text_cli(text)

    assert completed.returncode == 0, (
        completed.stdout.decode("utf-8", errors="backslashreplace"),
        completed.stderr.decode("utf-8", errors="backslashreplace"),
    )


def _noncomment_shell_lines(script: str) -> list[str]:
    """Return simple shell command lines without comments for static wiring checks."""
    return [line.split("#", 1)[0].strip() for line in script.splitlines()]


def _shell_assignment_names(
    lines: list[str], *required_values: str
) -> set[str]:
    names: set[str] = set()
    assignment = re.compile(
        r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?:\"|')(?P<value>.*?)(?:\"|')$"
    )
    for line in lines:
        match = assignment.match(line)
        if match and all(
            required_value in match.group("value")
            for required_value in required_values
        ):
            names.add(match.group("name"))
    return names


def _uses_shell_variable(command: str, name: str) -> bool:
    return f"${name}" in command or f"${{{name}}}" in command


def test_installer_copies_canonical_helper_and_guard_resolves_it_fail_closed():
    """Static only: do not make a temporary repository or invoke a real push."""
    installer_lines = _noncomment_shell_lines(INSTALLER.read_text(encoding="utf-8"))
    guard_lines = _noncomment_shell_lines(GUARD.read_text(encoding="utf-8"))
    installer = "\n".join(installer_lines)
    guard = "\n".join(guard_lines)

    # The installer must deliver an adjacent copy rather than leave an installed
    # hook dependent on whatever branch happens to be checked out at push time.
    helper_sources = _shell_assignment_names(
        installer_lines, "deploy/public_boundary.py"
    )
    helper_destinations = _shell_assignment_names(
        installer_lines, "hooks_dir", "public_boundary.py"
    )
    copy_commands = [
        line for line in installer_lines if re.match(r"^cp(?:\s|$)", line)
    ]

    assert "deploy/public_boundary.py" in installer
    assert helper_sources or any(
        "deploy/public_boundary.py" in command for command in copy_commands
    ), "installer must name deploy/public_boundary.py as its source"
    assert helper_destinations or any(
        "public_boundary.py" in command
        and _uses_shell_variable(command, "hooks_dir")
        for command in copy_commands
    ), "installer must name an installed public_boundary.py beside the hook"
    assert any(
        (
            any(_uses_shell_variable(command, source) for source in helper_sources)
            or "deploy/public_boundary.py" in command
        )
        and (
            any(
                _uses_shell_variable(command, destination)
                for destination in helper_destinations
            )
            or (
                "public_boundary.py" in command
                and _uses_shell_variable(command, "hooks_dir")
            )
        )
        for command in copy_commands
    ), "installer must copy the canonical helper beside the installed pre-push hook"

    # The copied guard must locate its sibling helper, feed it NUL paths, and
    # stop rather than silently pass a push if that copy is absent.
    guard_helpers = _shell_assignment_names(guard_lines, "public_boundary.py")
    guard_directories = _shell_assignment_names(guard_lines, "dirname")

    def references_guard_helper(command: str) -> bool:
        return "public_boundary.py" in command or any(
            _uses_shell_variable(command, helper) for helper in guard_helpers
        )

    assert guard_helpers or any(
        "public_boundary.py" in command for command in guard_lines
    ), "guard must name the installed public_boundary.py helper"
    assert "--stdin0" in guard
    assert "dirname" in guard and (
        "BASH_SOURCE" in guard or "$0" in guard
    ), "guard must resolve the installed helper relative to itself"
    assert (
        any(
            "public_boundary.py" in command and "dirname" in command
            for command in guard_lines
        )
        or any(
            "public_boundary.py" in command
            and any(
                _uses_shell_variable(command, directory)
                for directory in guard_directories
            )
            for command in guard_lines
        )
    ), "guard must derive the helper path from its own directory"
    assert any(
        "--stdin0" in command and references_guard_helper(command)
        for command in guard_lines
    ), "guard must invoke its sibling helper with the NUL protocol"

    helper_check_indices = [
        index
        for index, command in enumerate(guard_lines)
        if "-f" in command and references_guard_helper(command)
    ]
    assert helper_check_indices, "guard must check that its sibling helper exists"
    assert any(
        ("||" in guard_lines[index] or "!" in guard_lines[index])
        and (
            "abort" in "\n".join(guard_lines[index : index + 8])
            or re.search(r"\bexit\s+1\b", "\n".join(guard_lines[index : index + 8]))
        )
        for index in helper_check_indices
    ), "guard must fail closed when its sibling helper is missing"


def test_guard_pipes_annotated_tags_to_sibling_text_boundary_helper():
    """Static only: release annotation policy must have one canonical evaluator."""
    guard_lines = _noncomment_shell_lines(GUARD.read_text(encoding="utf-8"))
    guard = "\n".join(guard_lines)
    guard_helpers = _shell_assignment_names(guard_lines, "public_boundary.py")

    assert guard_helpers, "guard must retain its sibling public-boundary helper"
    assert any(
        "git cat-file tag" in command
        and "|" in command
        and "python3" in command
        and "--text" in command
        and re.search(r"--profile\s+public(?:\s|;|$)", command)
        and any(_uses_shell_variable(command, helper) for helper in guard_helpers)
        for command in guard_lines
    ), (
        "annotated tag content must be piped to the sibling helper in public "
        "annotation-text mode"
    )
    assert "FORBIDDEN_RE" not in guard, (
        "the helper must be the sole source of release annotation boundary policy"
    )

def test_rule_2_enumerates_commit_trees_with_nul_paths_not_git_log_names():
    """Static regression: history paths must come from each added commit tree."""
    commands = "\n".join(
        _noncomment_shell_lines(GUARD.read_text(encoding="utf-8"))
    )

    assert not re.search(r"\bgit\s+log\b[^\n]*\b--name-only\b", commands), (
        "RULE 2 must not use git log --name-only because commit separators and "
        "unusual names break its path producer"
    )

    history_loop = re.search(
        r"""
        \bgit\s+rev-list\b
        (?:\s+--[A-Za-z0-9-]+)*
        \s+(?:"?\$(?:\{)?range(?:\})?"?)
        \s*\|\s*while\s+IFS=\s*read\s+-r\s+
        (?P<commit>[A-Za-z_][A-Za-z0-9_]*)
        \s*;\s*do
        (?P<body>.*?)
        \bdone
        """,
        commands,
        flags=re.DOTALL | re.VERBOSE,
    )
    assert history_loop, (
        "RULE 2 must enumerate the added range with git rev-list and scan "
        "each emitted commit"
    )

    commit = history_loop.group("commit")
    commit_reference = rf"(?:\${commit}\b|\$\{{{commit}\}})"
    assert re.search(
        rf"\bgit\s+ls-tree\s+-r\s+-z\s+--name-only\s+"
        rf"(?:\"|')?{commit_reference}(?:\"|')?",
        history_loop.group("body"),
    ), (
        "each rev-list commit must be scanned with "
        "git ls-tree -r -z --name-only before the NUL helper input"
    )
