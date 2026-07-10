"""Repository profile contracts for the OSSRedact public/private split.

The public-boundary suite keeps the legacy public policy pinned.  This module
adds only the profile selection contracts that a private snapshot needs:
explicit public compatibility, narrow private allowances, fail-closed remote
identity detection, and CI profile selection.
"""
from __future__ import annotations

import importlib
import re
import shlex
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "public_boundary.py"
GUARD = ROOT / "deploy" / "pre-push-guard.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CPU_LOCK = ROOT / "deploy" / "requirements-gate-cpu.lock"
ZERO_SHA = "0" * 40
_UNAVAILABLE_NONZERO_SHA = "0123456789abcdef0123456789abcdef01234567"
_SYNTHETIC_PR_MERGE_CANDIDATE = "models/synthetic-pr-merge.safetensors"
_SYNTHETIC_TRUSTED_MAIN_CANDIDATE = "models/synthetic-trusted-main.safetensors"
_SYNTHETIC_TOPIC_CANDIDATE = "models/synthetic-review-candidate.safetensors"
_SYNTHETIC_TAILNET_MARKER = ".".join(("100", "64", "3", "4"))
_TAILNET_CIDR = ".".join(("100", "64")) + "/10"
_PUBLIC_COMMIT_MESSAGE_CASES = (
    ("private-path", "plans/release-checklist.md"),
    (
        "machine-pinned-artifact",
        "deploy/ossredact-gate-gpu-lab-host.service",
    ),
    ("tailnet-address", _SYNTHETIC_TAILNET_MARKER),
)
_PUBLIC_TAG_ANNOTATION_STEP = "Enforce public tag annotation boundary"
_RAW_COMMIT_HEADER_CASES = (
    ("author-private-path", "author", "plans/release-checklist.md"),
    ("committer-private-path", "committer", "plans/release-checklist.md"),
    ("author-tailnet-address", "author", _SYNTHETIC_TAILNET_MARKER),
    ("committer-tailnet-address", "committer", _SYNTHETIC_TAILNET_MARKER),
)

_TRANSFORMED_ARTIFACT_CASES = (
    ("public", "plans.zip", "internal-planning"),
    ("private", "plans.zip", None),
    ("public", "extension.tar.gz", "unreleased-extension"),
    ("private", "extension.tar.gz", None),
    ("public", "models.zip", "training-data-or-model"),
    ("private", "models.zip", "training-data-or-model"),
    ("public", "gateway-config.yaml.gz", "host-configuration"),
    ("private", "gateway-config.yaml.gz", "host-configuration"),
)
_PRIVATE_TAG_ANNOTATION_CASES = (
    ("common-host-configuration", "gateway-config.yaml", False),
    ("common-jsonl-corpus", "fixtures/private-tag-corpus.jsonl", False),
    ("private-planning", "plans/release-checklist.md", True),
    ("private-tailnet-only", _SYNTHETIC_TAILNET_MARKER, True),
    ("lightweight", None, True),
)




# Keep the repository namespace ahead of an unrelated installed ``deploy``
# package when this module is run from a different working directory.
sys.path.insert(0, str(ROOT))
public_boundary = importlib.import_module("deploy.public_boundary")


def _assert_rejected(path: str, *, profile: str) -> None:
    category = public_boundary.classify_path(path, profile=profile)
    assert isinstance(category, str) and category.strip(), (
        f"expected {path!r} to be rejected by the {profile!r} profile, "
        f"got {category!r}"
    )


def _run_cli(*arguments: str, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(HELPER), *arguments],
        cwd=ROOT,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


@pytest.mark.parametrize(
    ("path", "allowed"),
    (
        ("src/public_api.py", True),
        ("validation/stress_orgaddr_heldout.jsonl", True),
        ("plans/release-checklist.md", False),
        ("fixtures/ordinary.jsonl", False),
    ),
    ids=("ordinary-source", "allowlisted-jsonl", "internal-plan", "other-jsonl"),
)
def test_explicit_public_profile_preserves_legacy_public_boundary(
    path: str, allowed: bool
):
    """The named public profile keeps the existing release boundary intact."""
    category = public_boundary.classify_path(path, profile="public")

    assert (category is None) is allowed


@pytest.mark.parametrize(
    "artifact_path",
    (
        "gate/gate_service_gpu.py",
        "deploy/ossredact-gate-gpu.service",
        "deploy/requirements-gate-gpu.lock",
    ),
    ids=("gate-gpu-source", "generic-gpu-service", "generic-gpu-lock"),
)
def test_explicit_public_profile_allows_generic_gpu_artifacts(artifact_path: str):
    """Generic GPU sources and artifacts are not machine-pinned public rejects."""
    assert public_boundary.classify_path(artifact_path, profile="public") is None


@pytest.mark.parametrize(
    "path",
    (
        "AGENTS.md",
        "plans/release-checklist.md",
        "PRIOR-ART.md",
        "release/PRELAUNCH-AUDIT-findings.md",
        "docs/research/source-notes.md",
        "docs/superpowers/specs/internal-policy.md",
        "extension/src/background.ts",
    ),
    ids=(
        "agent-guidance",
        "plans",
        "prior-art",
        "prelaunch-audit",
        "research",
        "superpowers",
        "extension-source",
    ),
)
def test_private_profile_allows_only_approved_internal_development_categories(path: str):
    """Private snapshots admit the approved review material, not a broad bypass."""
    assert public_boundary.classify_path(path, profile="private") is None


@pytest.mark.parametrize(
    "path",
    (
        "",
        "/absolute/private.txt",
        "../outside-repository.txt",
        ".agents/worker-state.json",
        ".claude/settings.json",
        "datasets/synthetic/train.csv",
        "models/private-model.safetensors",
        "out/checkpoint.bin",
        "model.bak-20260709/checkpoint.bin",
        "artifacts/checkpoint.bak-20260709",
        "validation/realworld/receipt.txt",
        "output-data/customer-record.txt",
        "scratch/customer.pii.json",
        "gateway-config.yaml",
        "fixtures/ordinary.jsonl",
    ),
    ids=(
        "empty-path",
        "absolute-path",
        "parent-traversal",
        "agent-runtime-state",
        "claude-runtime-state",
        "dataset",
        "model",
        "checkpoint-output",
        "model-backup",
        "backup-artifact",
        "real-world-validation",
        "output-artifact",
        "pii-artifact",
        "host-configuration",
        "non-allowlisted-jsonl",
    ),
)
def test_private_profile_keeps_sensitive_categories_rejected(path: str):
    """Private review access never admits machine state, corpus data, or PII."""
    _assert_rejected(path, profile="private")



@pytest.mark.parametrize(
    ("profile", "path", "allowed"),
    (
        ("private", "extension/public/model/.gitkeep", True),
        ("private", "extension/public/model/config.json", False),
        ("private", "extension/public/model/onnx/model_int8.onnx", False),
        ("private", "extension/public/model/.GITKEEP", False),
        ("public", "extension/public/model/.gitkeep", False),
    ),
    ids=(
        "private-sentinel",
        "private-direct-generated-asset",
        "private-nested-generated-asset",
        "private-case-variant",
        "public-sentinel",
    ),
)
def test_extension_model_sentinel_is_the_only_private_model_path_exception(
    profile: str, path: str, allowed: bool
):
    """Private admits only the ignored model sentinel; public retains its extension block."""
    category = public_boundary.classify_path(path, profile=profile)

    assert (category is None) is allowed



@pytest.mark.parametrize(
    "artifact_path",
    (
        "deploy/ossredact-gate-gpu-lab-host.service",
        "deploy/requirements-gate-gpu-lab-host.lock",
    ),
    ids=("gpu-service", "gpu-lock"),
)
def test_generic_host_suffixed_gpu_artifacts_are_private_only(artifact_path: str):
    """Generic machine-pinned GPU artifacts remain private-only."""
    assert public_boundary.classify_path(artifact_path, profile="private") is None
    _assert_rejected(artifact_path, profile="public")

@pytest.mark.parametrize(
    ("profile", "path", "expected_category"),
    _TRANSFORMED_ARTIFACT_CASES,
    ids=(
        "public-plans-archive",
        "private-plans-archive",
        "public-extension-archive",
        "private-extension-archive",
        "public-models-archive",
        "private-models-archive",
        "public-gateway-config-archive",
        "private-gateway-config-archive",
    ),
)
def test_profiles_classify_transformed_sensitive_artifacts_by_source_category(
    profile: str, path: str, expected_category: str | None
):
    """Archives and compressed copies inherit their source artifact category."""
    assert (
        public_boundary.classify_path(path, profile=profile) == expected_category
    )


def test_cli_profile_flag_applies_the_selected_boundary_to_nul_paths():
    """The CLI must distinguish public release scans from private review scans."""
    internal_path = b"plans/release-checklist.md\0"

    public = _run_cli("--stdin0", "--profile", "public", stdin=internal_path)
    private = _run_cli("--stdin0", "--profile", "private", stdin=internal_path)

    assert public.returncode != 0
    assert private.returncode == 0, private.stderr.decode("utf-8", errors="replace")


@pytest.mark.parametrize(
    ("profile", "path", "expected_category"),
    _TRANSFORMED_ARTIFACT_CASES,
    ids=(
        "public-plans-archive",
        "private-plans-archive",
        "public-extension-archive",
        "private-extension-archive",
        "public-models-archive",
        "private-models-archive",
        "public-gateway-config-archive",
        "private-gateway-config-archive",
    ),
)
def test_cli_profile_boundary_rejects_transformed_sensitive_paths_from_stdin0(
    profile: str, path: str, expected_category: str | None
):
    """NUL-delimited scans keep the same archive policy as the classifier API."""
    completed = _run_cli(
        "--stdin0", "--profile", profile, stdin=path.encode("utf-8") + b"\0"
    )

    assert (completed.returncode != 0) is (expected_category is not None)

def test_cli_rejects_an_unknown_profile_with_the_supported_choices():
    """A typo cannot silently select a permissive boundary."""
    completed = _run_cli("--stdin0", "--profile", "partner", stdin=b"src/public_api.py\0")
    diagnostics = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")

    assert completed.returncode == 2
    assert "partner" in diagnostics
    assert "public" in diagnostics
    assert "private" in diagnostics


def _git(
    repository: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=None if environment is None else os.environ | environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _repository_with_installed_guard(tmp_path: Path, tracked_path: str) -> tuple[Path, str]:
    """Build a single-commit local repository without a remote or network access."""
    repository = tmp_path / "hook-fixture"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Boundary Test")
    _git(repository, "config", "user.email", "boundary-test@example.invalid")

    tracked = repository / tracked_path
    tracked.parent.mkdir(parents=True, exist_ok=True)
    tracked.write_text("fixture\n", encoding="utf-8")
    _git(repository, "add", "--", tracked_path)
    _git(repository, "commit", "--quiet", "-m", "boundary fixture")
    commit = _git(repository, "rev-parse", "HEAD")

    hooks = repository / "hooks"
    hooks.mkdir()
    for source, name in ((GUARD, "pre-push"), (HELPER, "public_boundary.py")):
        destination = hooks / name
        shutil.copy2(source, destination)
        destination.chmod(0o755)

    workflow_helper = repository / "deploy" / "public_boundary.py"
    workflow_helper.parent.mkdir()
    shutil.copy2(HELPER, workflow_helper)

    return repository, commit

def _commit_tracked_content(repository: Path, tracked_path: str, content: str) -> str:
    tracked = repository / tracked_path
    tracked.write_text(content, encoding="utf-8")
    _git(repository, "add", "--", tracked_path)
    _git(repository, "commit", "--quiet", "-m", "marker fixture")
    return _git(repository, "rev-parse", "HEAD")


def _configure_public_main(repository: Path) -> None:
    """Expose the fixture's main branch through a local public-origin remote."""
    remote = repository.parent / "public-origin.git"
    _git(repository, "init", "--bare", "--quiet", str(remote))
    _git(repository, "branch", "-M", "main")
    _git(repository, "remote", "add", "origin", str(remote))
    _git(repository, "push", "--quiet", "origin", "refs/heads/main")
    _git(
        repository,
        "fetch",
        "--quiet",
        "origin",
        "refs/heads/main:refs/remotes/origin/main",
    )


def _public_annotated_tag(
    repository: Path,
    commit: str,
    *,
    tag_name: str = "release-contract",
    message: str = "release contract",
) -> str:
    """Create an annotated tag on a commit already reachable from public main."""
    _configure_public_main(repository)
    _git(repository, "tag", "-a", tag_name, commit, "-m", message)
    return _git(repository, "rev-parse", f"refs/tags/{tag_name}")


def _public_lightweight_tag(
    repository: Path, commit: str, *, tag_name: str = "release-lightweight"
) -> str:
    """Create a lightweight tag on a commit already reachable from public main."""
    _configure_public_main(repository)
    _git(repository, "tag", tag_name, commit)
    return _git(repository, "rev-parse", f"refs/tags/{tag_name}")




def _run_guard(
    repository: Path,
    commit: str,
    *,
    remote_name: str,
    remote_url: str,
    local_ref: str = "refs/heads/feature",
    remote_ref: str = "refs/heads/feature",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(repository / "hooks" / "pre-push"), remote_name, remote_url],
        cwd=repository,
        input=f"{local_ref} {commit} {remote_ref} {ZERO_SHA}\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

@pytest.mark.parametrize(
    (
        "tracked_path",
        "remote_url",
        "local_ref",
        "remote_ref",
        "private_review",
    ),
    (
        (
            "plans/internal-context.md",
            "https://github.com/ZenSystemAI/OSSRedact-dev.git",
            "refs/heads/review",
            "refs/heads/review",
            True,
        ),
        (
            "src/public-marker.txt",
            "https://github.com/ZenSystemAI/OSSRedact.git",
            "refs/heads/main",
            "refs/heads/main",
            False,
        ),
    ),
    ids=("private-review-context", "public-export"),
)
def test_guard_scopes_tailnet_content_enforcement_to_public_exports(
    tmp_path: Path,
    tracked_path: str,
    remote_url: str,
    local_ref: str,
    remote_ref: str,
    private_review: bool,
):
    """A private review marker passes; the equivalent public marker is blocked."""
    repository, _ = _repository_with_installed_guard(tmp_path, tracked_path)
    commit = _commit_tracked_content(
        repository, tracked_path, f"synthetic marker {_SYNTHETIC_TAILNET_MARKER}\n"
    )

    completed = _run_guard(
        repository,
        commit,
        remote_name="origin",
        remote_url=remote_url,
        local_ref=local_ref,
        remote_ref=remote_ref,
    )

    if private_review:
        assert "unbound variable" not in completed.stderr
        assert completed.returncode == 0, completed.stderr
    else:
        assert completed.returncode != 0
        assert (
            f"carries internal tailnet ({_TAILNET_CIDR}) addresses in file content"
            in completed.stderr
        )
        assert _SYNTHETIC_TAILNET_MARKER not in (
            completed.stdout + completed.stderr
        )


def test_guard_defines_content_patterns_before_the_annotated_tag_scan(tmp_path: Path):
    """A safe public tag exercises both pattern variables before the tag scan exits."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_sha = _public_annotated_tag(repository, commit)

    completed = _run_guard(
        repository,
        tag_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/tags/release-contract",
        remote_ref="refs/tags/release-contract",
    )

    assert completed.returncode == 0, completed.stderr

    assert "unbound variable" not in completed.stderr


def test_guard_accepts_lightweight_tag_on_a_reachable_public_commit(tmp_path: Path):
    """A lightweight tag adds no annotation text and may point to public main."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_sha = _public_lightweight_tag(repository, commit)

    completed = _run_guard(
        repository,
        tag_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/tags/release-lightweight",
        remote_ref="refs/tags/release-lightweight",
    )

    assert completed.returncode == 0, completed.stderr


def test_guard_rejects_sensitive_annotated_tag_text_without_echoing_it(tmp_path: Path):
    """Public annotations retain their own candidate-free policy check."""
    candidate = "deploy/ossredact-gate-gpu-lab+host.service"
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_sha = _public_annotated_tag(
        repository,
        commit,
        tag_name="release-sensitive",
        message=f"Synthetic release notes cite {candidate}",
    )

    completed = _run_guard(
        repository,
        tag_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/tags/release-sensitive",
        remote_ref="refs/tags/release-sensitive",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert candidate not in diagnostics



def test_guard_treats_canonical_public_origin_as_the_public_profile(tmp_path: Path):
    """A public remote retains the main-only ref boundary even for safe paths."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")

    completed = _run_guard(
        repository,
        commit,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
    )

    assert completed.returncode != 0
    assert "only main" in completed.stderr

def test_guard_private_review_allows_the_extension_model_sentinel(tmp_path: Path):
    """The installed guard passes the one private extension-model sentinel path."""
    repository, commit = _repository_with_installed_guard(
        tmp_path, "extension/public/model/.gitkeep"
    )

    completed = _run_guard(
        repository,
        commit,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact-dev.git",
        local_ref="refs/heads/review",
        remote_ref="refs/heads/review",
    )

    assert completed.returncode == 0, completed.stderr




@pytest.mark.parametrize(
    ("remote_name", "remote_url"),
    (
        ("origin", "https://github.com/ZenSystemAI/OSSRedact-dev.git"),
        ("private", "https://github.com/ZenSystemAI/OSSRedact-dev.git"),
    ),
    ids=("canonical-private-origin", "legacy-private-alias"),
)
def test_guard_treats_known_private_identities_as_private_profile(
    tmp_path: Path, remote_name: str, remote_url: str
):
    """Known private remotes permit internal review branches and approved paths."""
    repository, commit = _repository_with_installed_guard(
        tmp_path, "plans/release-checklist.md"
    )

    completed = _run_guard(
        repository,
        commit,
        remote_name=remote_name,
        remote_url=remote_url,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("remote_name", "remote_url"),
    (
        ("mirror", "https://git.example.invalid/ossredact.git"),
        ("origin", "https://github.com/ZenSystemAI/OSSRedact-dev.git"),
        ("private", "https://github.com/ZenSystemAI/OSSRedact.git"),
    ),
    ids=("unknown-remote", "origin-private-url-mismatch", "private-public-url-mismatch"),
)
def test_guard_fails_closed_for_unknown_or_mismatched_remote_identities(
    tmp_path: Path, remote_name: str, remote_url: str
):
    """A name/URL disagreement cannot be downgraded to an unguarded push."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")

    completed = _run_guard(
        repository,
        commit,
        remote_name=remote_name,
        remote_url=remote_url,
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )

    assert completed.returncode != 0


def _repository_with_intermediate_tailnet_content(
    tmp_path: Path,
) -> tuple[Path, str, str]:
    """Create a clean tip after a safe path temporarily held a tailnet address."""
    repository, before_sha = _repository_with_installed_guard(
        tmp_path, "src/public_api.py"
    )
    intermediate_sha = _commit_tracked_content(
        repository,
        "src/public_api.py",
        f"synthetic address {_SYNTHETIC_TAILNET_MARKER}\n",
    )
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "synthetic safe tip\n"
    )

    assert _SYNTHETIC_TAILNET_MARKER in _git(
        repository, "show", f"{intermediate_sha}:src/public_api.py"
    )
    assert _SYNTHETIC_TAILNET_MARKER not in _git(
        repository, "show", f"{tip_sha}:src/public_api.py"
    )
    return repository, before_sha, tip_sha


def test_guard_rejects_tailnet_content_removed_from_a_later_public_commit(
    tmp_path: Path,
):
    """A clean tip cannot hide a public address that an added commit exposed."""
    repository, _, tip_sha = _repository_with_intermediate_tailnet_content(tmp_path)

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert _SYNTHETIC_TAILNET_MARKER not in diagnostics


def _repository_with_sensitive_added_commit_message(
    tmp_path: Path, candidate: str
) -> tuple[Path, str, str]:
    """Create an otherwise safe added commit whose only boundary hit is metadata."""
    repository, before_sha = _repository_with_installed_guard(
        tmp_path, "src/public_api.py"
    )
    _git(
        repository,
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        f"Synthetic release notes cite {candidate}",
    )
    return repository, before_sha, _git(repository, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    ("case", "candidate"),
    _PUBLIC_COMMIT_MESSAGE_CASES,
    ids=tuple(case for case, _ in _PUBLIC_COMMIT_MESSAGE_CASES),
)
def test_guard_rejects_sensitive_added_commit_messages_without_echoing_candidates(
    tmp_path: Path, case: str, candidate: str
):
    """Public pre-push checks must inspect added commit metadata, not only trees."""
    repository, _, tip_sha = _repository_with_sensitive_added_commit_message(
        tmp_path, candidate
    )

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0, case
    assert candidate not in diagnostics


def _repository_with_sensitive_added_commit_header(
    tmp_path: Path, *, header: str, candidate: str
) -> tuple[Path, str, str]:
    """Create a safe-body commit whose candidate occurs only in a raw header."""
    repository, before_sha = _repository_with_installed_guard(
        tmp_path, "src/public_api.py"
    )
    environment = {
        "GIT_AUTHOR_NAME": "Boundary Author",
        "GIT_AUTHOR_EMAIL": "author@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_NAME": "Boundary Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.invalid",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    }
    environment[f"GIT_{header.upper()}_NAME"] = f"Synthetic {candidate}"
    _git(
        repository,
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "synthetic safe commit body",
        environment=environment,
    )
    tip_sha = _git(repository, "rev-parse", "HEAD")
    raw_header, separator, message = _git(
        repository, "cat-file", "commit", tip_sha
    ).partition("\n\n")

    assert separator
    assert candidate in raw_header
    assert candidate not in message
    assert _git(repository, "show", "-s", "--format=%B", tip_sha) == (
        "synthetic safe commit body"
    )
    return repository, before_sha, tip_sha


@pytest.mark.parametrize(
    ("case", "header", "candidate"),
    _RAW_COMMIT_HEADER_CASES,
    ids=tuple(case for case, _, _ in _RAW_COMMIT_HEADER_CASES),
)
def test_guard_rejects_sensitive_added_commit_headers_without_echoing_candidates(
    tmp_path: Path, case: str, header: str, candidate: str
):
    """Pre-push inspection must cover raw author/committer headers, not just %B."""
    repository, _, tip_sha = _repository_with_sensitive_added_commit_header(
        tmp_path, header=header, candidate=candidate
    )

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0, case
    assert candidate not in diagnostics


def test_guard_rejects_a_local_marker_removed_from_an_intermediate_commit(
    tmp_path: Path,
):
    """Operator markers must scan every added tree without revealing their value."""
    marker = "synthetic-operator-marker"
    repository, _ = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    intermediate_sha = _commit_tracked_content(
        repository, "src/public_api.py", f"intermediate {marker}\n"
    )
    tip_sha = _commit_tracked_content(repository, "src/public_api.py", "safe tip\n")
    (repository / _git(repository, "rev-parse", "--git-dir") / "ossredact-guard-local").write_text(
        f"{re.escape(marker)}\n", encoding="utf-8"
    )

    assert marker in _git(repository, "show", f"{intermediate_sha}:src/public_api.py")
    assert marker not in _git(repository, "show", f"{tip_sha}:src/public_api.py")

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert marker not in diagnostics

def test_guard_rejects_a_local_marker_matching_only_an_intermediate_tree_path(
    tmp_path: Path,
):
    """Local marker quarantine must inspect added tree names, not only blob bytes."""
    marker = "synthetic-local-path-marker"
    candidate_path = f"src/{marker}.txt"
    repository, _ = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    candidate = repository / candidate_path
    candidate.write_text("synthetic clean blob\n", encoding="utf-8")
    _git(repository, "add", "--", candidate_path)
    _git(repository, "commit", "--quiet", "-m", "add marker path")
    intermediate_sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "rm", "--quiet", "--", candidate_path)
    _git(repository, "commit", "--quiet", "-m", "remove marker path")
    tip_sha = _git(repository, "rev-parse", "HEAD")
    (
        repository
        / _git(repository, "rev-parse", "--git-dir")
        / "ossredact-guard-local"
    ).write_text(f"{re.escape(marker)}\n", encoding="utf-8")

    assert candidate_path in _git(
        repository, "ls-tree", "-r", "--name-only", intermediate_sha
    ).splitlines()
    assert marker not in _git(repository, "show", f"{intermediate_sha}:{candidate_path}")
    assert candidate_path not in _git(
        repository, "ls-tree", "-r", "--name-only", tip_sha
    ).splitlines()

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert marker not in diagnostics


def test_guard_rejects_a_local_marker_in_raw_added_commit_metadata(
    tmp_path: Path,
):
    """Operator markers cover raw immutable metadata as well as tree content."""
    marker = "synthetic-header-marker"
    repository, _, tip_sha = _repository_with_sensitive_added_commit_header(
        tmp_path, header="author", candidate=marker
    )
    (repository / _git(repository, "rev-parse", "--git-dir") / "ossredact-guard-local").write_text(
        f"{re.escape(marker)}\n", encoding="utf-8"
    )

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref="refs/heads/main",
        remote_ref="refs/heads/main",
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert marker not in diagnostics


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)

def _run_ci_tailnet_hygiene(
    tmp_path: Path, repository_name: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Execute only the workflow's tailnet scan against a deterministic git shim."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["repo-hygiene"]["steps"]
    tailnet_steps = [
        step
        for step in steps
        if step.get("name") == "No internal tailnet addresses"
    ]
    assert len(tailnet_steps) == 1

    command_bin = tmp_path / "bin"
    command_bin.mkdir()
    calls = tmp_path / "git-calls"
    _write_executable(
        command_bin / "git",
        f"""#!/bin/sh
case "$1" in
  grep)
    printf '%s\n' "$*" >> "$GIT_CALLS"
    printf 'internal-context.md:1:{_SYNTHETIC_TAILNET_MARKER}\n'
    ;;
  *) printf 'unexpected fake git command: %s\n' "$1" >&2; exit 86 ;;
esac
""",
    )
    environment = {
        "GITHUB_REPOSITORY": repository_name,
        "GIT_CALLS": str(calls),
        "LC_ALL": "C",
        "PATH": f"{command_bin}{os.pathsep}{os.defpath}",
    }
    completed = subprocess.run(
        ["bash", "-eu", "-o", "pipefail", "-c", tailnet_steps[0]["run"]],
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    git_calls = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return completed, git_calls


@pytest.mark.parametrize(
    ("repository_name", "public_export"),
    (
        ("ZenSystemAI/OSSRedact", True),
        ("ZenSystemAI/OSSRedact-dev", False),
    ),
    ids=("canonical-public-repository", "private-development-repository"),
)
def test_ci_scopes_tailnet_disclosure_scan_to_public_exports(
    tmp_path: Path, repository_name: str, public_export: bool
):
    """Private snapshots retain internal context without running the public leak scan."""
    completed, git_calls = _run_ci_tailnet_hygiene(tmp_path, repository_name)

    assert bool(git_calls) is public_export
    assert (completed.returncode != 0) is public_export
    if public_export:
        assert f"Internal tailnet ({_TAILNET_CIDR}) address found." in completed.stderr
        assert _SYNTHETIC_TAILNET_MARKER not in (
            completed.stdout + completed.stderr
        )
    else:
        assert completed.stderr == ""



def test_extension_public_generated_model_and_runtime_assets_are_untracked():
    """Inspect index metadata only, never symlink targets, for generated extension assets."""
    completed = subprocess.run(
        ["git", "ls-files", "--stage", "-z", "--", "extension/public"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", errors="backslashreplace"
    )

    model_prefix = b"extension/public/model/"
    permitted_model_sentinel = model_prefix + b".gitkeep"
    runtime_prefix = b"extension/public/ort"
    forbidden: list[str] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        header, separator, path = record.partition(b"\t")
        assert separator, f"unexpected Git index record: {record!r}"
        mode = header.split(maxsplit=1)[0].decode("ascii")
        if path.startswith(model_prefix) and path != permitted_model_sentinel:
            forbidden.append(f"{mode} {path.decode('utf-8', errors='backslashreplace')}")
        if path == runtime_prefix or path.startswith(runtime_prefix + b"/"):
            forbidden.append(f"{mode} {path.decode('utf-8', errors='backslashreplace')}")

    assert not forbidden, (
        "generated extension model/runtime assets must be untracked; "
        f"found index entries: {', '.join(forbidden)}"
    )


_PUBLIC_ADDED_COMMIT_STEP = "Enforce public added-commit boundary"


def _repo_hygiene_step(name: str) -> dict[str, object]:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["repo-hygiene"]["steps"]
    matching_steps = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    assert len(matching_steps) == 1, (
        f"repo-hygiene must define exactly one {name!r} step"
    )
    return matching_steps[0]


def _repository_with_intermediate_forbidden_commit(
    tmp_path: Path, *, forbidden_path: str
) -> tuple[Path, str, str, str]:
    """Create a clean tip whose added history contains one forbidden path."""
    repository = tmp_path / "workflow-history"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Boundary Test")
    _git(repository, "config", "user.email", "boundary-test@example.invalid")

    safe_path = "src/public_api.py"
    (repository / "src").mkdir()
    (repository / safe_path).write_text("safe root\n", encoding="utf-8")
    _git(repository, "add", "--", safe_path)
    _git(repository, "commit", "--quiet", "-m", "safe root")
    before_sha = _git(repository, "rev-parse", "HEAD")

    forbidden = repository / forbidden_path
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_text("synthetic boundary fixture\n", encoding="utf-8")
    _git(repository, "add", "--", forbidden_path)
    _git(repository, "commit", "--quiet", "-m", "intermediate forbidden path")
    intermediate_sha = _git(repository, "rev-parse", "HEAD")

    _git(repository, "rm", "--quiet", "--", forbidden_path)
    _git(repository, "commit", "--quiet", "-m", "remove intermediate path")
    tip_sha = _git(repository, "rev-parse", "HEAD")

    assert forbidden_path in _git(
        repository, "ls-tree", "-r", "--name-only", intermediate_sha
    ).splitlines()
    assert forbidden_path not in _git(
        repository, "ls-tree", "-r", "--name-only", tip_sha
    ).splitlines()

    helper = repository / "deploy" / "public_boundary.py"
    helper.parent.mkdir()
    shutil.copy2(HELPER, helper)
    return repository, before_sha, tip_sha, forbidden_path


def _repository_with_private_topic(
    tmp_path: Path,
    *,
    trusted_main_metadata: str | None = None,
    with_origin_main: bool = True,
) -> tuple[Path, str]:
    """Create a private review branch above an optional trusted remote main."""
    repository, _ = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    if trusted_main_metadata is not None:
        _git(
            repository,
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            f"synthetic trusted main metadata {trusted_main_metadata}",
        )
    trusted_main = _git(repository, "rev-parse", "HEAD")
    if with_origin_main:
        _configure_public_main(repository)
    _git(repository, "checkout", "--quiet", "-b", "review/ci-boundary")
    return repository, trusted_main


def _commit_unrelated_safe_topic(repository: Path) -> str:
    """Create a clean topic head that cannot descend from the current branch."""
    _git(repository, "checkout", "--quiet", "--orphan", "review/unrelated")
    _git(repository, "rm", "--quiet", "-r", "-f", "--", ".")
    safe_path = repository / "src" / "unrelated.py"
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text("unrelated safe topic\n", encoding="utf-8")
    _git(repository, "add", "--", "src/unrelated.py")
    _git(repository, "commit", "--quiet", "-m", "unrelated safe topic")
    return _git(repository, "rev-parse", "HEAD")


def _repository_with_synthetic_pr_merge(
    tmp_path: Path, *, forbidden_metadata: str
) -> tuple[Path, str, str, str]:
    """Build a PR head plus a checked-out synthetic merge commit."""
    repository, base_sha = _repository_with_private_topic(tmp_path)
    pr_head_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe pull request head\n"
    )
    _git(repository, "checkout", "--quiet", "--detach", base_sha)
    _git(
        repository,
        "merge",
        "--no-ff",
        "--quiet",
        "-m",
        f"synthetic pull request merge metadata {forbidden_metadata}",
        pr_head_sha,
    )
    merge_sha = _git(repository, "rev-parse", "HEAD")
    merge_metadata = _git(repository, "cat-file", "commit", merge_sha)

    assert forbidden_metadata in merge_metadata
    assert forbidden_metadata not in _git(
        repository, "ls-tree", "-r", "--name-only", merge_sha
    )
    assert len(_git(repository, "show", "-s", "--format=%P", merge_sha).split()) == 2
    return repository, base_sha, pr_head_sha, merge_sha


def _private_topic_context(ref_name: str = "review/ci-boundary") -> dict[str, str]:
    """Return GitHub push context for a private review branch."""
    return {
        "GITHUB_REF": f"refs/heads/{ref_name}",
        "GITHUB_REF_NAME": ref_name,
        "GITHUB_REF_TYPE": "branch",
    }


def _render_ci_context(
    value: str,
    *,
    before_sha: str,
    base_sha: str | None = None,
    tip_sha: str,
    repository_name: str,
    event_name: str = "push",
    pr_head_sha: str | None = None,
    ref: str | None = None,
    ref_name: str | None = None,
    ref_type: str | None = None,
) -> str:
    replacements = {
        r"\$\{\{\s*github\.event\.before\s*\}\}": before_sha,
        r"\$\{\{\s*github\.event_name\s*\}\}": event_name,
        r"\$\{\{\s*github\.repository\s*\}\}": repository_name,
        r"\$\{\{\s*github\.sha\s*\}\}": tip_sha,
        r"\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\|\|\s*github\.sha\s*\}\}": (
            pr_head_sha if pr_head_sha is not None else tip_sha
        ),
    }
    if base_sha is not None:
        replacements[
            r"\$\{\{\s*github\.event\.pull_request\.base\.sha\s*\|\|\s*github\.event\.before\s*\}\}"
        ] = base_sha
    if ref is not None:
        replacements[r"\$\{\{\s*github\.ref\s*\}\}"] = ref
    if ref_name is not None:
        replacements[r"\$\{\{\s*github\.ref_name\s*\}\}"] = ref_name
    if ref_type is not None:
        replacements[r"\$\{\{\s*github\.ref_type\s*\}\}"] = ref_type
    for pattern, replacement in replacements.items():
        value = re.sub(pattern, replacement, value)
    return value


def _run_ci_repo_hygiene_step(
    repository: Path,
    *,
    step_name: str,
    repository_name: str,
    before_sha: str,
    tip_sha: str,
    base_sha: str | None = None,
    event_name: str = "push",
    pr_head_sha: str | None = None,
    include_event_before: bool = True,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one repo-hygiene script with local Git history and GitHub context."""
    step = _repo_hygiene_step(step_name)
    script = step.get("run")
    assert isinstance(script, str) and script.strip(), (
        f"{step_name} must provide an executable shell script"
    )

    step_environment = step.get("env", {})
    assert isinstance(step_environment, dict), (
        f"{step_name} environment must be a mapping"
    )

    environment = os.environ.copy()
    for key in (
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_REF_TYPE",
        "GITHUB_EVENT_BEFORE",
        "GITHUB_BASE_REF",
        "GITHUB_HEAD_REF",
    ):
        environment.pop(key, None)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_REPOSITORY": repository_name,
            "GITHUB_SHA": tip_sha,
            "GITHUB_WORKSPACE": str(repository),
            "LC_ALL": "C",
        }
    )
    if include_event_before:
        environment["GITHUB_EVENT_BEFORE"] = before_sha
    if extra_environment is not None:
        assert all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in extra_environment.items()
        ), f"{step_name} extra environment entries must be strings"
        environment.update(extra_environment)

    ref = environment.get("GITHUB_REF")
    ref_name = environment.get("GITHUB_REF_NAME")
    ref_type = environment.get("GITHUB_REF_TYPE")
    for key, value in step_environment.items():
        assert isinstance(key, str) and isinstance(value, str), (
            f"{step_name} environment entries must be strings"
        )
        environment[key] = _render_ci_context(
            value,
            before_sha=before_sha,
            tip_sha=tip_sha,
            repository_name=repository_name,
            base_sha=base_sha,
            event_name=event_name,
            pr_head_sha=pr_head_sha,
            ref=ref,
            ref_name=ref_name,
            ref_type=ref_type,
        )

    return subprocess.run(
        [
            "bash",
            "-eu",
            "-o",
            "pipefail",
            "-c",
            _render_ci_context(
                script,
                before_sha=before_sha,
                tip_sha=tip_sha,
                repository_name=repository_name,
                base_sha=base_sha,
                event_name=event_name,
                pr_head_sha=pr_head_sha,
                ref=ref,
                ref_name=ref_name,
                ref_type=ref_type,
            ),
        ],
        cwd=repository,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def _run_ci_added_commit_boundary(
    repository: Path,
    *,
    repository_name: str,
    before_sha: str,
    tip_sha: str,
    base_sha: str | None = None,
    event_name: str = "push",
    pr_head_sha: str | None = None,
    include_event_before: bool = True,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the added-commit boundary step against deterministic local history."""
    return _run_ci_repo_hygiene_step(
        repository,
        step_name=_PUBLIC_ADDED_COMMIT_STEP,
        repository_name=repository_name,
        before_sha=before_sha,
        tip_sha=tip_sha,
        base_sha=base_sha,
        event_name=event_name,
        pr_head_sha=pr_head_sha,
        include_event_before=include_event_before,
        extra_environment=extra_environment,
    )


def _run_ci_tag_annotation_boundary(
    repository: Path,
    *,
    tag_ref: str,
    tag_sha: str,
    repository_name: str = "ZenSystemAI/OSSRedact",
) -> subprocess.CompletedProcess[str]:
    """Run the public tag-metadata step with the event context GitHub supplies."""
    return _run_ci_repo_hygiene_step(
        repository,
        step_name=_PUBLIC_TAG_ANNOTATION_STEP,
        repository_name=repository_name,
        before_sha=ZERO_SHA,
        tip_sha=tag_sha,
        extra_environment={
            "GITHUB_REF": tag_ref,
            "GITHUB_REF_NAME": tag_ref.rsplit("/", maxsplit=1)[-1],
            "GITHUB_REF_TYPE": "tag",
        },
    )

def _run_ci_tracked_path_boundary(
    tmp_path: Path, *, repository_name: str, tracked_path: str
) -> subprocess.CompletedProcess[str]:
    """Execute the real tracked-path workflow step with a deterministic Git index."""
    step = _repo_hygiene_step("Enforce repository tracked-path boundary")
    script = step.get("run")
    assert isinstance(script, str) and script.strip()

    command_bin = tmp_path / "bin"
    command_bin.mkdir()
    _write_executable(
        command_bin / "git",
        """#!/bin/sh
case "$1" in
  ls-files) printf '%s\\000' "$TRACKED_PATH" ;;
  *) printf 'unexpected fake git command: %s\\n' "$1" >&2; exit 86 ;;
esac
""",
    )
    _write_executable(
        command_bin / "python",
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n",
    )
    environment = {
        "GITHUB_REPOSITORY": repository_name,
        "LC_ALL": "C",
        "PATH": f"{command_bin}{os.pathsep}{os.defpath}",
        "TRACKED_PATH": tracked_path,
    }
    return subprocess.run(
        ["bash", "-eu", "-o", "pipefail", "-c", script],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def test_repo_hygiene_checkout_fetches_full_history():
    """The added-commit boundary cannot inspect commits omitted by a shallow checkout."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["repo-hygiene"]["steps"]
    checkouts = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("uses") == "actions/checkout@v4"
    ]

    assert len(checkouts) == 1, "repo-hygiene must have exactly one checkout"
    checkout_options = checkouts[0].get("with", {})
    assert isinstance(checkout_options, dict), (
        "repo-hygiene checkout options must be a mapping"
    )
    assert checkout_options.get("fetch-depth") == 0, (
        "repo-hygiene must fetch full history before scanning added commits"
    )


def test_ci_added_commit_boundary_scans_incremental_history_and_requires_fallback_context(
    tmp_path: Path,
):
    """Private planning is allowed in incremental ranges, not ungated zero-base history."""
    repository, before_sha, tip_sha, forbidden_path = (
        _repository_with_intermediate_forbidden_commit(
            tmp_path, forbidden_path="plans/intermediate-private.md"
        )
    )
    cases = (
        ("public-incremental-history", "ZenSystemAI/OSSRedact", before_sha, True),
        ("private-incremental-history", "ZenSystemAI/OSSRedact-dev", before_sha, False),
        ("public-new-branch-history", "ZenSystemAI/OSSRedact", ZERO_SHA, True),
        ("private-new-branch-history", "ZenSystemAI/OSSRedact-dev", ZERO_SHA, True),
    )

    for name, repository_name, event_before, should_reject in cases:
        completed = _run_ci_added_commit_boundary(
            repository,
            repository_name=repository_name,
            before_sha=event_before,
            tip_sha=tip_sha,
        )

        assert (completed.returncode != 0) is should_reject, name
        if should_reject:
            diagnostics = completed.stdout + completed.stderr
            assert forbidden_path not in diagnostics, name
        else:
            assert completed.returncode == 0, f"{name}: {completed.stderr}"

@pytest.mark.parametrize(
    "repository_name",
    ("ZenSystemAI/OSSRedact", "ZenSystemAI/OSSRedact-dev"),
    ids=("public", "private"),
)
def test_ci_tracked_path_boundary_rejects_common_sensitive_paths_without_echoing(
    tmp_path: Path, repository_name: str
):
    """Tracked-tree failures preserve the path boundary without publishing the path."""
    candidate = "gateway-config.yaml"
    completed = _run_ci_tracked_path_boundary(
        tmp_path, repository_name=repository_name, tracked_path=candidate
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert candidate not in diagnostics

def test_ci_added_commit_boundary_preserves_github_interpolated_base_sha_without_event_before(
    tmp_path: Path,
):
    """GitHub bases are authoritative; only raw local expressions use the harness fallback."""
    repository, _, tip_sha, _ = _repository_with_intermediate_forbidden_commit(
        tmp_path, forbidden_path="plans/intermediate-private.md"
    )
    base_sha = _git(repository, "rev-parse", f"{tip_sha}^")

    local_harness = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=base_sha,
        tip_sha=tip_sha,
    )
    assert local_harness.returncode == 0, local_harness.stderr

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=base_sha,
        tip_sha=tip_sha,
        base_sha=base_sha,
        include_event_before=False,
    )

    assert completed.returncode == 0, completed.stderr

def test_ci_added_commit_boundary_ignores_inherited_tag_context_for_default_branch_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A tag-run parent cannot turn a default branch range into tag processing."""
    repository, trusted_main = _repository_with_private_topic(tmp_path)
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe inherited tag context candidate\n"
    )
    inherited_tag_ref = "refs/tags/inherited-release"
    for key, value in {
        "GITHUB_REF": inherited_tag_ref,
        "GITHUB_REF_NAME": "inherited-release",
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_EVENT_BEFORE": ZERO_SHA,
        "GITHUB_BASE_REF": "release",
        "GITHUB_HEAD_REF": "release-candidate",
    }.items():
        monkeypatch.setenv(key, value)

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=trusted_main,
        tip_sha=tip_sha,
        base_sha=trusted_main,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_ci_added_commit_boundary_scans_pull_request_head_not_synthetic_merge(
    tmp_path: Path,
):
    """PR validation excludes generated merge metadata from the added range."""
    repository, base_sha, pr_head_sha, merge_sha = _repository_with_synthetic_pr_merge(
        tmp_path, forbidden_metadata=_SYNTHETIC_PR_MERGE_CANDIDATE
    )
    merge_metadata = _git(repository, "cat-file", "commit", merge_sha)
    classifier = _run_cli(
        "--text",
        "--profile",
        "private",
        stdin=merge_metadata.encode("utf-8"),
    )
    classifier_diagnostics = (
        classifier.stdout + classifier.stderr
    ).decode("utf-8", errors="replace")

    assert classifier.returncode != 0
    assert _SYNTHETIC_PR_MERGE_CANDIDATE not in classifier_diagnostics
    assert _git(repository, "rev-parse", "HEAD") == merge_sha

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=ZERO_SHA,
        tip_sha=merge_sha,
        base_sha=base_sha,
        event_name="pull_request",
        pr_head_sha=pr_head_sha,
        include_event_before=False,
        extra_environment={
            "GITHUB_REF": "refs/pull/7/merge",
            "GITHUB_REF_NAME": "7/merge",
            "GITHUB_REF_TYPE": "branch",
        },
    )
    diagnostics = completed.stdout + completed.stderr

    assert _SYNTHETIC_PR_MERGE_CANDIDATE not in diagnostics
    assert completed.returncode == 0, diagnostics


def test_ci_added_commit_boundary_private_topic_falls_back_to_trusted_main_range(
    tmp_path: Path,
):
    """A rewritten private topic can scan only commits added above origin/main."""
    repository, trusted_main = _repository_with_private_topic(tmp_path)
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe rewritten private topic\n"
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=trusted_main,
        tip_sha=tip_sha,
        base_sha=_UNAVAILABLE_NONZERO_SHA,
        include_event_before=False,
        extra_environment=_private_topic_context(),
    )

    assert completed.returncode == 0, completed.stderr

def test_ci_added_commit_boundary_private_review_force_push_falls_back_from_resolved_non_ancestor(
    tmp_path: Path,
):
    """A private review force-push can replace a resolvable old topic tip."""
    repository, trusted_main = _repository_with_private_topic(tmp_path)
    old_topic_tip = _commit_tracked_content(
        repository, "src/old_topic.py", "safe old private topic\n"
    )
    _git(repository, "reset", "--quiet", "--hard", trusted_main)
    tip_sha = _commit_tracked_content(
        repository, "src/new_topic.py", "safe rewritten private topic\n"
    )

    assert _git(repository, "rev-parse", "--verify", f"{old_topic_tip}^{{commit}}") == (
        old_topic_tip
    )
    assert _git(repository, "merge-base", old_topic_tip, tip_sha) == trusted_main
    assert _git(repository, "rev-parse", "refs/heads/review/ci-boundary") == tip_sha

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=old_topic_tip,
        base_sha=old_topic_tip,
        tip_sha=tip_sha,
        extra_environment=_private_topic_context(),
    )
    diagnostics = completed.stdout + completed.stderr

    assert old_topic_tip not in diagnostics
    assert tip_sha not in diagnostics
    assert completed.returncode == 0, diagnostics


def test_ci_added_commit_boundary_private_topic_scans_removed_forbidden_candidate(
    tmp_path: Path,
):
    """Trusted-main fallback retains earlier private-topic commits in its range."""
    repository, trusted_main = _repository_with_private_topic(tmp_path)
    forbidden = repository / _SYNTHETIC_TOPIC_CANDIDATE
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_text("synthetic forbidden candidate\n", encoding="utf-8")
    _git(repository, "add", "--", _SYNTHETIC_TOPIC_CANDIDATE)
    _git(repository, "commit", "--quiet", "-m", "add forbidden topic candidate")
    intermediate_sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "rm", "--quiet", "--", _SYNTHETIC_TOPIC_CANDIDATE)
    _git(repository, "commit", "--quiet", "-m", "remove forbidden topic candidate")
    tip_sha = _git(repository, "rev-parse", "HEAD")

    assert _SYNTHETIC_TOPIC_CANDIDATE in _git(
        repository, "ls-tree", "-r", "--name-only", intermediate_sha
    )
    assert _SYNTHETIC_TOPIC_CANDIDATE not in _git(
        repository, "ls-tree", "-r", "--name-only", tip_sha
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=trusted_main,
        tip_sha=tip_sha,
        base_sha=_UNAVAILABLE_NONZERO_SHA,
        include_event_before=False,
        extra_environment=_private_topic_context(),
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert "Added-commit tree path boundary failed." in diagnostics
    assert _SYNTHETIC_TOPIC_CANDIDATE not in diagnostics


def test_ci_added_commit_boundary_private_zero_base_ignores_trusted_main_metadata(
    tmp_path: Path,
):
    """A zero private base scans from trusted main rather than all reachable history."""
    repository, trusted_main = _repository_with_private_topic(
        tmp_path, trusted_main_metadata=_SYNTHETIC_TRUSTED_MAIN_CANDIDATE
    )
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe zero-base private topic\n"
    )
    trusted_main_metadata = _git(repository, "cat-file", "commit", trusted_main)
    classifier = _run_cli(
        "--text",
        "--profile",
        "private",
        stdin=trusted_main_metadata.encode("utf-8"),
    )
    classifier_diagnostics = (
        classifier.stdout + classifier.stderr
    ).decode("utf-8", errors="replace")

    assert _SYNTHETIC_TRUSTED_MAIN_CANDIDATE not in _git(
        repository, "ls-tree", "-r", "--name-only", trusted_main
    )
    assert classifier.returncode != 0
    assert _SYNTHETIC_TRUSTED_MAIN_CANDIDATE not in classifier_diagnostics

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=ZERO_SHA,
        tip_sha=tip_sha,
        base_sha=ZERO_SHA,
        include_event_before=False,
        extra_environment=_private_topic_context(),
    )
    diagnostics = completed.stdout + completed.stderr

    assert _SYNTHETIC_TRUSTED_MAIN_CANDIDATE not in diagnostics
    assert completed.returncode == 0, diagnostics


@pytest.mark.parametrize(
    "base_sha",
    (_UNAVAILABLE_NONZERO_SHA, ZERO_SHA),
    ids=("unavailable-base", "zero-base"),
)
def test_ci_added_commit_boundary_public_rejects_unavailable_or_zero_base(
    tmp_path: Path, base_sha: str
):
    """Public history never widens to a trusted-main fallback after a missing base."""
    repository, trusted_main = _repository_with_private_topic(tmp_path)
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe public fallback candidate\n"
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=trusted_main,
        tip_sha=tip_sha,
        base_sha=base_sha,
        include_event_before=False,
        extra_environment=_private_topic_context(),
    )
    diagnostics = completed.stdout + completed.stderr

    assert base_sha not in diagnostics
    assert completed.returncode != 0
    assert "Added-commit boundary" in diagnostics


@pytest.mark.parametrize(
    (
        "case",
        "repository_name",
        "ref",
        "ref_name",
        "ref_type",
        "with_origin_main",
        "unrelated_topic",
    ),
    (
        (
            "public-topic",
            "ZenSystemAI/OSSRedact",
            "refs/heads/review/ci-boundary",
            "review/ci-boundary",
            "branch",
            True,
            False,
        ),
        (
            "private-main",
            "ZenSystemAI/OSSRedact-dev",
            "refs/heads/main",
            "main",
            "branch",
            True,
            False,
        ),
        (
            "private-tag",
            "ZenSystemAI/OSSRedact-dev",
            "refs/tags/ci-boundary",
            "ci-boundary",
            "tag",
            True,
            False,
        ),
        (
            "private-detached",
            "ZenSystemAI/OSSRedact-dev",
            "",
            "",
            "",
            True,
            False,
        ),
        (
            "private-missing-origin-main",
            "ZenSystemAI/OSSRedact-dev",
            "refs/heads/review/ci-boundary",
            "review/ci-boundary",
            "branch",
            False,
            False,
        ),
        (
            "private-unrelated-origin-main",
            "ZenSystemAI/OSSRedact-dev",
            "refs/heads/review/unrelated",
            "review/unrelated",
            "branch",
            True,
            True,
        ),
    ),
    ids=(
        "public-topic",
        "private-main",
        "private-tag",
        "private-detached",
        "private-missing-origin-main",
        "private-unrelated-origin-main",
    ),
)
@pytest.mark.parametrize(
    "base_sha",
    (_UNAVAILABLE_NONZERO_SHA, ZERO_SHA),
    ids=("unavailable-base", "zero-base"),
)
def test_ci_added_commit_boundary_fails_closed_for_ineligible_private_fallback(
    tmp_path: Path,
    case: str,
    repository_name: str,
    ref: str,
    ref_name: str,
    ref_type: str,
    with_origin_main: bool,
    unrelated_topic: bool,
    base_sha: str,
):
    """Only private review pushes above ancestral origin/main may replace a base."""
    repository, trusted_main = _repository_with_private_topic(
        tmp_path, with_origin_main=with_origin_main
    )
    if unrelated_topic:
        tip_sha = _commit_unrelated_safe_topic(repository)
    else:
        tip_sha = _commit_tracked_content(
            repository, "src/public_api.py", f"safe {case} candidate\n"
        )
    if case == "private-detached":
        _git(repository, "checkout", "--quiet", "--detach", tip_sha)

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name=repository_name,
        before_sha=trusted_main,
        tip_sha=tip_sha,
        base_sha=base_sha,
        include_event_before=False,
        extra_environment={
            "GITHUB_REF": ref,
            "GITHUB_REF_NAME": ref_name,
            "GITHUB_REF_TYPE": ref_type,
        },
    )
    diagnostics = completed.stdout + completed.stderr

    assert base_sha not in diagnostics, case
    assert completed.returncode != 0, case
    assert "Added-commit boundary" in diagnostics, case


def test_ci_added_commit_boundary_rejects_resolved_non_ancestral_base(
    tmp_path: Path,
):
    """A resolved base must still be an ancestor of the selected scan head."""
    repository, base_sha = _repository_with_installed_guard(
        tmp_path, "src/public_api.py"
    )
    tip_sha = _commit_unrelated_safe_topic(repository)

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=base_sha,
        tip_sha=tip_sha,
        base_sha=base_sha,
        include_event_before=False,
        extra_environment=_private_topic_context("review/unrelated"),
    )
    diagnostics = completed.stdout + completed.stderr

    assert base_sha not in diagnostics
    assert tip_sha not in diagnostics
    assert completed.returncode != 0
    assert "Added-commit boundary" in diagnostics


def test_ci_added_commit_boundary_rejects_tailnet_content_removed_from_later_commit(
    tmp_path: Path,
):
    """Server-side history validation must scan content in every added tree."""
    repository, before_sha, tip_sha = _repository_with_intermediate_tailnet_content(
        tmp_path
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=before_sha,
        tip_sha=tip_sha,
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert _SYNTHETIC_TAILNET_MARKER not in diagnostics


@pytest.mark.parametrize(
    ("case", "candidate"),
    _PUBLIC_COMMIT_MESSAGE_CASES,
    ids=tuple(case for case, _ in _PUBLIC_COMMIT_MESSAGE_CASES),
)
def test_ci_added_commit_boundary_rejects_sensitive_commit_messages_without_echoing(
    tmp_path: Path, case: str, candidate: str
):
    """Server-side public history must include each added commit's metadata."""
    repository, before_sha, tip_sha = _repository_with_sensitive_added_commit_message(
        tmp_path, candidate
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=before_sha,
        tip_sha=tip_sha,
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0, case
    assert candidate not in diagnostics


@pytest.mark.parametrize(
    ("case", "header", "candidate"),
    _RAW_COMMIT_HEADER_CASES,
    ids=tuple(case for case, _, _ in _RAW_COMMIT_HEADER_CASES),
)
def test_ci_added_commit_boundary_rejects_sensitive_raw_headers_without_echoing(
    tmp_path: Path, case: str, header: str, candidate: str
):
    """CI must inspect complete raw commit objects rather than only %B bodies."""
    repository, before_sha, tip_sha = _repository_with_sensitive_added_commit_header(
        tmp_path, header=header, candidate=candidate
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=before_sha,
        tip_sha=tip_sha,
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0, case
    assert candidate not in diagnostics


@pytest.mark.parametrize(
    ("case", "forbidden_path", "allowed"),
    (
        ("private-host-configuration", "gateway-config.yaml", False),
        ("private-nonallowlisted-jsonl", "fixtures/intermediate-corpus.jsonl", False),
        ("private-only-plans", "plans/intermediate-private.md", True),
    ),
    ids=(
        "host-configuration",
        "nonallowlisted-jsonl",
        "private-only-plans",
    ),
)
def test_ci_added_commit_boundary_applies_private_profile_to_every_added_tree(
    tmp_path: Path, case: str, forbidden_path: str, allowed: bool
):
    """Private CI scans intermediate trees with its policy, not a broad bypass."""
    repository, before_sha, tip_sha, _ = _repository_with_intermediate_forbidden_commit(
        tmp_path, forbidden_path=forbidden_path
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=before_sha,
        tip_sha=tip_sha,
    )

    diagnostics = completed.stdout + completed.stderr
    assert (completed.returncode == 0) is allowed, case
    if not allowed:
        assert forbidden_path not in diagnostics, case


@pytest.mark.parametrize(
    ("case", "header", "candidate", "allowed"),
    (
        ("private-common-author-header", "author", "gateway-config.yaml", False),
        (
            "private-only-committer-header",
            "committer",
            "plans/release-checklist.md",
            True,
        ),
        (
            "private-tailnet-header",
            "author",
            _SYNTHETIC_TAILNET_MARKER,
            True,
        ),
    ),
    ids=("common-sensitive", "private-only-path", "tailnet-public-only"),
)
def test_ci_added_commit_boundary_applies_private_profile_to_raw_headers(
    tmp_path: Path, case: str, header: str, candidate: str, allowed: bool
):
    """Private CI keeps canonical path policy while tailnet rules stay public-only."""
    repository, before_sha, tip_sha = _repository_with_sensitive_added_commit_header(
        tmp_path, header=header, candidate=candidate
    )

    completed = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=before_sha,
        tip_sha=tip_sha,
    )
    diagnostics = completed.stdout + completed.stderr

    assert (completed.returncode == 0) is allowed, case
    if not allowed:
        assert candidate not in diagnostics


@pytest.mark.parametrize(
    ("case", "header", "candidate", "allowed"),
    (
        ("private-common-author-header", "author", "gateway-config.yaml", False),
        (
            "private-only-committer-header",
            "committer",
            "plans/release-checklist.md",
            True,
        ),
        (
            "private-tailnet-header",
            "author",
            _SYNTHETIC_TAILNET_MARKER,
            True,
        ),
    ),
    ids=("common-sensitive", "private-only-path", "tailnet-public-only"),
)
def test_guard_applies_private_profile_to_raw_headers(
    tmp_path: Path, case: str, header: str, candidate: str, allowed: bool
):
    """Private pre-push scans raw metadata by path policy without public tailnet rules."""
    repository, _, tip_sha = _repository_with_sensitive_added_commit_header(
        tmp_path, header=header, candidate=candidate
    )

    completed = _run_guard(
        repository,
        tip_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact-dev.git",
    )
    diagnostics = completed.stdout + completed.stderr

    assert (completed.returncode == 0) is allowed, case
    if not allowed:
        assert candidate not in diagnostics


def _workflow_push_configuration() -> dict[str, object]:
    """Return the explicit push trigger configuration from the CI workflow."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow.get("on") or workflow.get(True)
    assert isinstance(triggers, dict), "CI must declare its event triggers"
    push = triggers.get("push")
    assert isinstance(push, dict), "repo hygiene must declare a push trigger"
    return push


def test_repo_hygiene_runs_for_every_tag_push():
    """Repository publication checks must run for tag refs, not branches alone."""
    assert _workflow_push_configuration().get("tags") == ["**"]

def test_repo_hygiene_runs_tag_boundary_before_added_commit_boundary():
    """Tag metadata validation must finish before tag events reach range validation."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["repo-hygiene"]["steps"]
    assert isinstance(steps, list), "repo-hygiene steps must be ordered"
    tag_step = _repo_hygiene_step(_PUBLIC_TAG_ANNOTATION_STEP)
    added_commit_step = _repo_hygiene_step(_PUBLIC_ADDED_COMMIT_STEP)

    assert steps.index(tag_step) < steps.index(added_commit_step)


def _repository_with_public_tag_cases(
    tmp_path: Path,
) -> tuple[Path, str, str, str]:
    """Create safe lightweight and sensitive annotated public tags on main."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    _configure_public_main(repository)
    _git(repository, "tag", "release-lightweight", commit)
    candidate = "deploy/ossredact-gate-gpu-lab+host.service"
    _git(
        repository,
        "tag",
        "-a",
        "release-sensitive",
        commit,
        "-m",
        f"Synthetic release notes cite {candidate}",
    )
    return (
        repository,
        _git(repository, "rev-parse", "refs/tags/release-lightweight"),
        _git(repository, "rev-parse", "refs/tags/release-sensitive"),
        candidate,
    )

def _private_tag_for_metadata_case(
    repository: Path,
    commit: str,
    *,
    tag_name: str,
    candidate: str | None,
) -> str:
    """Create a private lightweight or annotated tag on one safe commit."""
    if candidate is None:
        _git(repository, "tag", tag_name, commit)
    else:
        _git(
            repository,
            "tag",
            "-a",
            tag_name,
            commit,
            "-m",
            f"Synthetic private release notes cite {candidate}",
        )
    return _git(repository, "rev-parse", f"refs/tags/{tag_name}")


def test_ci_tag_annotation_boundary_accepts_lightweight_and_redacts_annotated_hits(
    tmp_path: Path,
):
    """The server permits public lightweight tags but rejects private annotations."""
    repository, lightweight_sha, sensitive_sha, candidate = (
        _repository_with_public_tag_cases(tmp_path)
    )
    cases = (
        ("lightweight", "refs/tags/release-lightweight", lightweight_sha, True),
        ("sensitive-annotation", "refs/tags/release-sensitive", sensitive_sha, False),
    )

    for name, tag_ref, tag_sha, allowed in cases:
        completed = _run_ci_tag_annotation_boundary(
            repository, tag_ref=tag_ref, tag_sha=tag_sha
        )
        diagnostics = completed.stdout + completed.stderr

        assert (completed.returncode == 0) is allowed, name
        if not allowed:
            assert candidate not in diagnostics

@pytest.mark.parametrize(
    ("case", "candidate", "allowed"),
    _PRIVATE_TAG_ANNOTATION_CASES,
    ids=tuple(case for case, _, _ in _PRIVATE_TAG_ANNOTATION_CASES),
)
def test_guard_applies_private_profile_to_annotated_tag_metadata(
    tmp_path: Path, case: str, candidate: str | None, allowed: bool
):
    """Private tags retain common-sensitive annotation checks but allow private context."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_name = f"private-{case}"
    tag_sha = _private_tag_for_metadata_case(
        repository, commit, tag_name=tag_name, candidate=candidate
    )
    tag_ref = f"refs/tags/{tag_name}"

    completed = _run_guard(
        repository,
        tag_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact-dev.git",
        local_ref=tag_ref,
        remote_ref=tag_ref,
    )
    diagnostics = completed.stdout + completed.stderr

    assert (completed.returncode == 0) is allowed, case
    if not allowed:
        assert candidate is not None
        assert candidate not in diagnostics


@pytest.mark.parametrize(
    ("case", "candidate", "allowed"),
    _PRIVATE_TAG_ANNOTATION_CASES,
    ids=tuple(case for case, _, _ in _PRIVATE_TAG_ANNOTATION_CASES),
)
def test_ci_applies_private_profile_to_annotated_tag_metadata(
    tmp_path: Path, case: str, candidate: str | None, allowed: bool
):
    """Private CI tag checks match the guard's metadata policy and output privacy."""
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_name = f"private-ci-{case}"
    tag_sha = _private_tag_for_metadata_case(
        repository, commit, tag_name=tag_name, candidate=candidate
    )
    tag_ref = f"refs/tags/{tag_name}"

    completed = _run_ci_tag_annotation_boundary(
        repository,
        tag_ref=tag_ref,
        tag_sha=tag_sha,
        repository_name="ZenSystemAI/OSSRedact-dev",
    )
    diagnostics = completed.stdout + completed.stderr

    assert (completed.returncode == 0) is allowed, case
    if not allowed:
        assert candidate is not None
        assert candidate not in diagnostics


def _repository_with_tag_reachability_cases(
    tmp_path: Path,
) -> tuple[Path, tuple[tuple[str, str, str, bool], ...]]:
    """Create public and local-only tag targets of both supported tag object types."""
    repository, public_commit = _repository_with_installed_guard(
        tmp_path, "src/public_api.py"
    )
    _configure_public_main(repository)
    _git(repository, "tag", "reachable-lightweight", public_commit)
    _git(
        repository,
        "tag",
        "-a",
        "reachable-annotated",
        public_commit,
        "-m",
        "safe release annotation",
    )

    local_only_commit = _commit_tracked_content(
        repository, "src/public_api.py", "not yet on public main\n"
    )
    _git(repository, "tag", "unreachable-lightweight", local_only_commit)
    _git(
        repository,
        "tag",
        "-a",
        "unreachable-annotated",
        local_only_commit,
        "-m",
        "safe release annotation",
    )

    cases = (
        (
            "reachable-lightweight",
            "refs/tags/reachable-lightweight",
            _git(repository, "rev-parse", "refs/tags/reachable-lightweight"),
            True,
        ),
        (
            "reachable-annotated",
            "refs/tags/reachable-annotated",
            _git(repository, "rev-parse", "refs/tags/reachable-annotated"),
            True,
        ),
        (
            "unreachable-lightweight",
            "refs/tags/unreachable-lightweight",
            _git(repository, "rev-parse", "refs/tags/unreachable-lightweight"),
            False,
        ),
        (
            "unreachable-annotated",
            "refs/tags/unreachable-annotated",
            _git(repository, "rev-parse", "refs/tags/unreachable-annotated"),
            False,
        ),
    )
    return repository, cases


def test_ci_tag_boundary_requires_lightweight_and_annotated_targets_on_public_main(
    tmp_path: Path,
):
    """Server-side tags may publish only commits already reachable from public main."""
    repository, cases = _repository_with_tag_reachability_cases(tmp_path)

    for name, tag_ref, tag_sha, allowed in cases:
        completed = _run_ci_tag_annotation_boundary(
            repository, tag_ref=tag_ref, tag_sha=tag_sha
        )

        assert (completed.returncode == 0) is allowed, name


@pytest.mark.parametrize(
    "tag_case",
    ("reachable-lightweight", "reachable-annotated"),
)
def test_ci_safe_reachable_public_tag_pushes_pass_after_tag_boundary(
    tmp_path: Path,
    tag_case: str,
):
    """Reachable public tags have no added commits after dedicated tag validation."""
    repository, cases = _repository_with_tag_reachability_cases(tmp_path)
    matching_cases = [case for case in cases if case[0] == tag_case]
    assert len(matching_cases) == 1, tag_case
    _, tag_ref, tag_sha, _ = matching_cases[0]

    tag_boundary = _run_ci_tag_annotation_boundary(
        repository, tag_ref=tag_ref, tag_sha=tag_sha
    )
    assert tag_boundary.returncode == 0, f"{tag_case}: {tag_boundary.stderr}"
    tag_context = {
        "GITHUB_REF": tag_ref,
        "GITHUB_REF_NAME": tag_ref.rsplit("/", maxsplit=1)[-1],
        "GITHUB_REF_TYPE": "tag",
    }

    added_commit_boundary = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact",
        before_sha=ZERO_SHA,
        base_sha=ZERO_SHA,
        tip_sha=tag_sha,
        event_name="push",
        extra_environment=tag_context,
    )

    assert added_commit_boundary.returncode == 0, (
        f"{tag_case}: {added_commit_boundary.stdout}{added_commit_boundary.stderr}"
    )


def test_ci_safe_private_hotfix_tag_push_passes_after_tag_boundary(
    tmp_path: Path,
):
    """A private direct-hotfix tag scans its safe commit above trusted main."""
    repository, _ = _repository_with_private_topic(tmp_path)
    tip_sha = _commit_tracked_content(
        repository, "src/public_api.py", "safe private tag hotfix\n"
    )
    tag_name = "private-hotfix"
    tag_ref = f"refs/tags/{tag_name}"
    tag_sha = _private_tag_for_metadata_case(
        repository, tip_sha, tag_name=tag_name, candidate=None
    )
    tag_boundary = _run_ci_tag_annotation_boundary(
        repository,
        tag_ref=tag_ref,
        tag_sha=tag_sha,
        repository_name="ZenSystemAI/OSSRedact-dev",
    )
    assert tag_boundary.returncode == 0, tag_boundary.stderr

    added_commit_boundary = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=ZERO_SHA,
        base_sha=ZERO_SHA,
        tip_sha=tag_sha,
        event_name="push",
        extra_environment={
            "GITHUB_REF": tag_ref,
            "GITHUB_REF_NAME": tag_name,
            "GITHUB_REF_TYPE": "tag",
        },
    )

    assert added_commit_boundary.returncode == 0, (
        added_commit_boundary.stdout + added_commit_boundary.stderr
    )


def test_ci_private_tag_push_scans_removed_forbidden_history(
    tmp_path: Path,
):
    """Private tags scan every unique commit above main, not only their target tree."""
    repository, _ = _repository_with_private_topic(tmp_path)
    candidate = _SYNTHETIC_TOPIC_CANDIDATE
    forbidden = repository / candidate
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_text("synthetic forbidden tag history\n", encoding="utf-8")
    _git(repository, "add", "--", candidate)
    _git(repository, "commit", "--quiet", "-m", "add forbidden tag history")
    _git(repository, "rm", "--quiet", "--", candidate)
    _git(repository, "commit", "--quiet", "-m", "remove forbidden tag history")
    tip_sha = _git(repository, "rev-parse", "HEAD")
    tag_name = "private-history"
    tag_ref = f"refs/tags/{tag_name}"
    tag_sha = _private_tag_for_metadata_case(
        repository, tip_sha, tag_name=tag_name, candidate=None
    )
    assert candidate not in _git(
        repository, "ls-tree", "-r", "--name-only", tip_sha
    ).splitlines()

    tag_boundary = _run_ci_tag_annotation_boundary(
        repository,
        tag_ref=tag_ref,
        tag_sha=tag_sha,
        repository_name="ZenSystemAI/OSSRedact-dev",
    )
    assert tag_boundary.returncode == 0, tag_boundary.stderr
    added_commit_boundary = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=ZERO_SHA,
        base_sha=ZERO_SHA,
        tip_sha=tag_sha,
        event_name="push",
        extra_environment={
            "GITHUB_REF": tag_ref,
            "GITHUB_REF_NAME": tag_name,
            "GITHUB_REF_TYPE": "tag",
        },
    )
    diagnostics = added_commit_boundary.stdout + added_commit_boundary.stderr

    assert added_commit_boundary.returncode != 0
    assert "Added-commit tree path boundary failed." in diagnostics
    assert candidate not in diagnostics


def test_ci_private_orphan_tag_push_fails_closed_after_tag_boundary(
    tmp_path: Path,
):
    """A private tag unrelated to origin/main cannot select an added-commit range."""
    repository, _ = _repository_with_private_topic(tmp_path)
    _commit_unrelated_safe_topic(repository)
    workflow_helper = repository / "deploy" / "public_boundary.py"
    workflow_helper.parent.mkdir(exist_ok=True)
    shutil.copy2(HELPER, workflow_helper)
    _git(repository, "add", "--", "deploy/public_boundary.py")
    _git(repository, "commit", "--quiet", "-m", "restore boundary helper")
    tip_sha = _git(repository, "rev-parse", "HEAD")
    tag_name = "private-orphan"
    tag_ref = f"refs/tags/{tag_name}"
    tag_sha = _private_tag_for_metadata_case(
        repository, tip_sha, tag_name=tag_name, candidate=None
    )

    tag_boundary = _run_ci_tag_annotation_boundary(
        repository,
        tag_ref=tag_ref,
        tag_sha=tag_sha,
        repository_name="ZenSystemAI/OSSRedact-dev",
    )
    assert tag_boundary.returncode == 0, tag_boundary.stderr
    added_commit_boundary = _run_ci_added_commit_boundary(
        repository,
        repository_name="ZenSystemAI/OSSRedact-dev",
        before_sha=ZERO_SHA,
        base_sha=ZERO_SHA,
        tip_sha=tag_sha,
        event_name="push",
        extra_environment={
            "GITHUB_REF": tag_ref,
            "GITHUB_REF_NAME": tag_name,
            "GITHUB_REF_TYPE": "tag",
        },
    )
    diagnostics = added_commit_boundary.stdout + added_commit_boundary.stderr

    assert added_commit_boundary.returncode != 0
    assert "Added-commit boundary" in diagnostics


def _require_git_tag_name(tag_name: str) -> None:
    """Skip only if the installed Git rejects a synthetic tag namespace."""
    completed = subprocess.run(
        ["git", "check-ref-format", f"refs/tags/{tag_name}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip("installed Git rejects this synthetic tag namespace")


@pytest.mark.parametrize(
    "tag_name",
    (
        "plans/release-checklist.md",
        f"release-{_SYNTHETIC_TAILNET_MARKER}",
    ),
    ids=("private-path", "tailnet-address"),
)
def test_guard_rejects_sensitive_public_tag_ref_names_without_echoing_them(
    tmp_path: Path, tag_name: str
):
    """Local public tag names share the canonical path and tailnet boundaries."""
    _require_git_tag_name(tag_name)
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_sha = _public_lightweight_tag(repository, commit, tag_name=tag_name)
    tag_ref = f"refs/tags/{tag_name}"

    completed = _run_guard(
        repository,
        tag_sha,
        remote_name="origin",
        remote_url="https://github.com/ZenSystemAI/OSSRedact.git",
        local_ref=tag_ref,
        remote_ref=tag_ref,
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert tag_name not in diagnostics


@pytest.mark.parametrize(
    "tag_name",
    (
        "plans/release-checklist.md",
        f"release-{_SYNTHETIC_TAILNET_MARKER}",
    ),
    ids=("private-path", "tailnet-address"),
)
def test_ci_rejects_sensitive_public_tag_ref_names_without_echoing_them(
    tmp_path: Path, tag_name: str
):
    """Server-side tag names share the canonical path and tailnet boundaries."""
    _require_git_tag_name(tag_name)
    repository, commit = _repository_with_installed_guard(tmp_path, "src/public_api.py")
    tag_sha = _public_lightweight_tag(repository, commit, tag_name=tag_name)
    tag_ref = f"refs/tags/{tag_name}"

    completed = _run_ci_tag_annotation_boundary(
        repository, tag_ref=tag_ref, tag_sha=tag_sha
    )
    diagnostics = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert tag_name not in diagnostics


def test_public_cpu_lock_header_is_host_and_hardware_neutral():
    """Public CPU dependency metadata states only a generic validated environment."""
    header = [
        line
        for line in CPU_LOCK.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    ]

    assert header == [
        "# Frozen manifest for a validated CPU deployment environment (~/.ossredact/venv) -- INT8 ONNX base model + proxy.",
        "# Pins redaction behavior + the egress runtime.",
        "# regen: ~/.ossredact/venv/bin/pip freeze > deploy/requirements-gate-cpu.lock",
    ]


def _workflow_boundary_profile(
    tmp_path: Path, repository_name: str
) -> str | None:
    """Run the repo-hygiene workflow commands against hermetic command shims."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["repo-hygiene"]["steps"]
    tracked_path_steps = [
        step
        for step in steps
        if step.get("name")
        in {
            "Enforce repository tracked-path boundary",
            "Enforce public tracked-path boundary",
        }
    ]
    assert len(tracked_path_steps) == 1
    run_scripts = [tracked_path_steps[0]["run"]]

    command_bin = tmp_path / "bin"
    command_bin.mkdir()
    capture = tmp_path / "python-invocations"
    _write_executable(
        command_bin / "git",
        """#!/bin/sh
case "$1" in
  ls-files) printf 'src/public_api.py\\0' ;;
  grep) exit 1 ;;
  *) printf 'unexpected fake git command: %s\\n' "$1" >&2; exit 86 ;;
esac
""",
    )
    python_shim = """#!/bin/sh
printf '%s\\037' "$@" >> "$CAPTURE"
printf '\\n' >> "$CAPTURE"
cat >/dev/null
"""
    _write_executable(command_bin / "python", python_shim)
    _write_executable(command_bin / "python3", python_shim)

    environment = {
        "CAPTURE": str(capture),
        "GITHUB_REPOSITORY": repository_name,
        "LC_ALL": "C",
        "PATH": f"{command_bin}{os.pathsep}{os.defpath}",
    }
    for script in run_scripts:
        completed = subprocess.run(
            ["bash", "-eu", "-o", "pipefail", "-c", script],
            cwd=tmp_path,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr

    invocations = [
        line.split("\x1f")[:-1]
        for line in capture.read_text(encoding="utf-8").splitlines()
    ]
    boundary_invocations = [
        arguments
        for arguments in invocations
        if arguments and Path(arguments[0]).name == "public_boundary.py"
    ]
    assert len(boundary_invocations) == 1
    arguments = boundary_invocations[0]
    assert "--stdin0" in arguments
    assert "--profile" in arguments
    return arguments[arguments.index("--profile") + 1]


@pytest.mark.parametrize(
    ("repository_name", "expected_profile"),
    (
        ("ZenSystemAI/OSSRedact", "public"),
        ("ZenSystemAI/OSSRedact-dev", "private"),
    ),
    ids=("canonical-public-repository", "canonical-private-repository"),
)
def test_ci_selects_the_boundary_profile_for_its_repository_identity(
    tmp_path: Path, repository_name: str, expected_profile: str
):
    """CI runs the same helper under the repository's explicit profile."""
    assert _workflow_boundary_profile(tmp_path, repository_name) == expected_profile


def test_ci_torch_free_python_step_keeps_both_repository_profile_contracts():
    """The shared torch-free pytest process cannot omit either boundary suite."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["gate-floor"]["steps"]
    torch_free_steps = [
        step
        for step in steps
        if step.get("name") == "Run torch-free gate + training + validation tests"
    ]

    assert len(torch_free_steps) == 1
    pytest_arguments = shlex.split(torch_free_steps[0]["run"])
    assert "pytest" in pytest_arguments
    assert "deploy/test_public_boundary.py" in pytest_arguments
    assert "deploy/test_repository_profiles.py" in pytest_arguments
