#!/usr/bin/env python3
"""Hermetic contract tests for validation/run_v12_gates.sh (Phase 5 fail-closed shell).

These tests never touch a real model, dataset, or training log. They copy the shell into a
private mini-repo, install stub interpreters at the hard-coded .venv-* paths, and assert the
acceptance mechanics the shell must provide:

1. Regenerate validation/stress_orgaddr_heldout.jsonl before any evaluator run.
2. Fail nonzero immediately if regeneration differs from the tracked fixture (before eval).
3. Run bar_check_v11.py against EVERY evaluator output JSON, not only one gate.
4. Propagate a bar_check failure as a nonzero shell exit (no catch-and-continue).

Expected production seams (minimal; add to run_v12_gates.sh if still missing):

  # After REPO/MODEL/PY/DEV/DTYPE setup, before run_eval:
  "$PY" "$REPO/validation/build_stress_heldout.py"
  if ! cmp -s "$REPO/validation/stress_orgaddr_heldout.jsonl" \\
              "$REPO/validation/stress_orgaddr_heldout.jsonl.expected" 2>/dev/null; then
      # preferred: regenerate into a temp file, then:
      #   cmp -s "$tmp_regen" "$REPO/validation/stress_orgaddr_heldout.jsonl"
      # or: git -C "$REPO" diff --exit-code -- validation/stress_orgaddr_heldout.jsonl
      echo "stress fixture drifted after regeneration" >&2
      exit 1
  fi

  # After all run_eval calls, bar-check every output (not swallowed):
  for gate in heldout-v11r5 generator-holdout stress-orgaddr; do
    "$PY" "$REPO/validation/bar_check_v11.py" "/tmp/v12-gate-$gate.json"
  done

  # Remove: `... bar_check_v11.py ... || echo "(bar_check needs...)"`
  # Keep: set -euo pipefail so bar failure and fixture drift exit nonzero.

Optional hermetic overrides (nice-to-have; not required by this harness):
  V12_GATE_OUT_DIR  directory for v12-gate-*.json (default /tmp)
  V12_SKIP_FLOOR=1  skip the model-independent pytest floor suites

Run:
  python -m pytest validation/test_run_v12_gates.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SHELL_SRC = REPO_ROOT / "validation" / "run_v12_gates.sh"

# Evaluator gate names the shell must produce and bar-check.
EVAL_GATES = ("heldout-v11r5", "generator-holdout", "stress-orgaddr")
STRESS_REL = Path("validation") / "stress_orgaddr_heldout.jsonl"


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)




def _install_stub_python(bin_path: Path, log_path: Path, mode: str) -> None:
    """Install a python shim that logs invocations and never loads a model.

    mode:
      clean     - build_stress rewrites fixture to identical content; bar always passes
      drift     - build_stress rewrites fixture to different content
      bar_fail  - bar_check exits 1 for any input carrying _harness_force_bar_fail
                  (eval stub marks every gate JSON with the fail marker)
    """
    body = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        LOG={shlex_quote(str(log_path))}
        MODE={shlex_quote(mode)}
        # argv[0] is this shim; remaining args are what the shell passed to python.
        printf 'PY %s\\n' "$*" >>"$LOG"

        if [ "$#" -eq 0 ]; then
          echo "stub python: missing script" >&2
          exit 2
        fi

        # `python -m pytest ...` floor suites: always green, never real tests.
        if [ "$1" = "-m" ] && [ "${{2:-}}" = "pytest" ]; then
          printf 'PYTEST %s\\n' "$*" >>"$LOG"
          exit 0
        fi

        SCRIPT="$1"
        shift || true
        BASE="$(basename "$SCRIPT")"

        case "$BASE" in
          build_stress_heldout.py)
            printf 'BUILD_STRESS\\n' >>"$LOG"
            # Locate fixture next to the script (validation/stress_orgaddr_heldout.jsonl).
            FIX="$(cd "$(dirname "$SCRIPT")" && pwd)/stress_orgaddr_heldout.jsonl"
            if [ "$MODE" = "drift" ]; then
              printf 'drifted-synthetic-row\\n' >"$FIX"
            else
              # rewrite with identical bytes when the tracked fixture already matches
              if [ -f "$FIX" ]; then
                tmp="$FIX.tmp.$$"
                cat "$FIX" >"$tmp"
                mv "$tmp" "$FIX"
              else
                printf '{{"input":"synthetic","output":{{"spans":[],"entities":{{}}}},"meta":{{"src":"stress_heldout"}}}}\\n' >"$FIX"
              fi
            fi
            exit 0
            ;;
          eval_labelaware.py)
            NAME="$(basename "${{GPU_GATE_OUT:-/tmp/v12-gate-unknown.json}}" .json)"
            GATE="${{NAME#v12-gate-}}"
            printf 'EVAL %s out=%s val=%s\\n' "$GATE" "${{GPU_GATE_OUT:-}}" "${{GPU_GATE_VAL:-}}" >>"$LOG"
            if [ -z "${{GPU_GATE_OUT:-}}" ]; then
              echo "stub eval: GPU_GATE_OUT unset" >&2
              exit 2
            fi
            # Emit synthetic evaluator JSON. bar_fail mode marks every gate as failing
            # so both the current heldout-only bar path and the Phase 5 all-gates path
            # can prove fail-closed propagation.
            if [ "$MODE" = "bar_fail" ]; then
              python3 - <<'PY' "$GPU_GATE_OUT"
        import json, sys
        path = sys.argv[1]
        labels = ["government_id","payment_card","card_cvv","card_expiry","secret","password",
                  "account_number","iban","sensitive_account_id","email","person","date_of_birth",
                  "tax_id","organization","address"]
        per = {{lab: {{"gold": 10, "pred": 10, "recall_labeled": 1.0, "precision": 1.0, "f1": 1.0}} for lab in labels}}
        per["person"]["recall_labeled"] = 0.5
        per["person"]["f1"] = 0.5
        data = {{
            "model": "stub-fail",
            "n_rows": 3,
            "_harness_force_bar_fail": True,
            "modes": {{"model": {{
                "labeled_recall": 0.5, "precision": 1.0, "f1": 0.5, "clean_fp": 0,
                "per_label": per,
            }}}},
        }}
        open(path, "w", encoding="utf-8").write(json.dumps(data))
        print("stub eval wrote", path)
        PY
            else
              python3 - <<'PY' "$GPU_GATE_OUT"
        import json, sys
        path = sys.argv[1]
        labels = ["government_id","payment_card","card_cvv","card_expiry","secret","password",
                  "account_number","iban","sensitive_account_id","email","person","date_of_birth",
                  "tax_id","organization","address"]
        per = {{lab: {{"gold": 10, "pred": 10, "recall_labeled": 1.0, "precision": 1.0, "f1": 1.0}} for lab in labels}}
        data = {{
            "model": "stub-pass",
            "n_rows": 3,
            "modes": {{"model": {{
                "labeled_recall": 1.0, "precision": 1.0, "f1": 1.0, "clean_fp": 0,
                "per_label": per,
            }}}},
        }}
        open(path, "w", encoding="utf-8").write(json.dumps(data))
        print("stub eval wrote", path)
        PY
            fi
            exit 0
            ;;
          bar_check_v11.py)
            printf 'BAR' >>"$LOG"
            for p in "$@"; do printf ' %s' "$p" >>"$LOG"; done
            printf '\\n' >>"$LOG"
            # Log each path on its own line for easy assertions.
            for p in "$@"; do
              printf 'BAR_PATH %s\\n' "$p" >>"$LOG"
            done
            if [ "$#" -eq 0 ]; then
              echo "stub bar_check: no inputs" >&2
              exit 1
            fi
            fail=0
            for p in "$@"; do
              if [ ! -f "$p" ]; then
                echo "stub bar_check: missing $p" >&2
                fail=1
                continue
              fi
              if grep -q '"_harness_force_bar_fail": true' "$p" 2>/dev/null \\
                 || grep -q '"_harness_force_bar_fail":true' "$p" 2>/dev/null; then
                echo "VERDICT: FAIL (harness)" >&2
                fail=1
              else
                echo "VERDICT: *** PASS ***"
              fi
            done
            exit "$fail"
            ;;
          *)
            echo "stub python: unexpected script $SCRIPT" >&2
            exit 2
            ;;
        esac
        """
    )
    _write_executable(bin_path, body)


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _build_sandbox(tmp_path: Path, mode: str) -> tuple[Path, Path, Path]:
    """Create a mini-repo with the real shell + stub interpreters + synthetic fixtures."""
    root = tmp_path / "repo"
    val = root / "validation"
    val.mkdir(parents=True)

    # Production shell under test (byte copy; no production edit).
    shutil.copy2(SHELL_SRC, val / "run_v12_gates.sh")
    (val / "run_v12_gates.sh").chmod(
        (val / "run_v12_gates.sh").stat().st_mode | stat.S_IXUSR
    )

    # Synthetic scripts the shell invokes by path; content is irrelevant (stub dispatches on basename).
    for name in (
        "eval_labelaware.py",
        "bar_check_v11.py",
        "build_stress_heldout.py",
    ):
        (val / name).write_text(f"# stub surface for {name}\n", encoding="utf-8")

    # Tracked stress fixture (synthetic).
    stress = root / STRESS_REL
    stress.write_text(
        json.dumps(
            {
                "input": "Ship to 200 King St W, please confirm.",
                "output": {"spans": [[8, 21, "address"]], "entities": {}},
                "meta": {"src": "stress_heldout"},
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # Dataset paths referenced by the shell (content unused by stubs).
    for rel in (
        "datasets/pii-heldout-v11r5/test.jsonl",
        "datasets/pii-merged-v12-stage1/generator_holdout.jsonl",
    ):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"input":"synthetic"}\n', encoding="utf-8")

    # Default model dir string only; never loaded.
    (root / "models" / "pii-gpu-opf-v12").mkdir(parents=True)

    log_path = tmp_path / "invocations.log"
    log_path.write_text("", encoding="utf-8")

    train_py = root / ".venv-train" / "bin" / "python"
    test_py = root / ".venv-test" / "bin" / "python"
    _install_stub_python(train_py, log_path, mode)
    # Floor suites use a separate interpreter path; same shim is fine.
    _install_stub_python(test_py, log_path, mode)

    return root, log_path, val / "run_v12_gates.sh"


def _run_shell(script: Path, root: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Force CPU dtype branch without needing CUDA; stubs ignore device.
    env["GATE_DEVICE"] = "cpu"
    env["GPU_GATE_DTYPE"] = "float32"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(script)],
        cwd=str(root),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _log_lines(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    return [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _bar_paths(log_path: Path) -> list[str]:
    out = []
    for ln in _log_lines(log_path):
        if ln.startswith("BAR_PATH "):
            out.append(ln[len("BAR_PATH ") :])
    return out


def _eval_gates(log_path: Path) -> list[str]:
    gates = []
    for ln in _log_lines(log_path):
        if ln.startswith("EVAL "):
            # "EVAL <gate> out=... val=..."
            gates.append(ln.split()[1])
    return gates


# --------------------------------------------------------------------------- tests


def test_shell_regenerates_stress_fixture_before_eval(tmp_path: Path):
    """Shell must invoke build_stress_heldout before evaluator runs (tracked synthetic corpus)."""
    root, log_path, script = _build_sandbox(tmp_path, mode="clean")
    proc = _run_shell(script, root)
    lines = _log_lines(log_path)
    builds = [i for i, ln in enumerate(lines) if ln == "BUILD_STRESS"]
    evals = [i for i, ln in enumerate(lines) if ln.startswith("EVAL ")]

    assert builds, (
        "expected production seam: run build_stress_heldout.py before evals\\n"
        f"exit={proc.returncode}\\nstdout:\\n{proc.stdout}\\nstderr:\\n{proc.stderr}\\nlog:\\n"
        + "\\n".join(lines)
    )
    assert evals, "stub eval never ran; sandbox wiring broken"
    assert min(builds) < min(evals), "stress regeneration must precede every evaluator call"


def test_shell_fails_closed_when_regenerated_stress_differs(tmp_path: Path):
    """If regeneration rewrites the tracked fixture, shell must exit nonzero before relying on it."""
    root, log_path, script = _build_sandbox(tmp_path, mode="drift")
    stress = root / STRESS_REL
    before = stress.read_text(encoding="utf-8")
    proc = _run_shell(script, root)
    lines = _log_lines(log_path)

    assert any(ln == "BUILD_STRESS" for ln in lines), (
        "expected production seam: regenerate stress fixture then cmp/diff against tracked file\\n"
        f"exit={proc.returncode}\\nlog:\\n" + "\\n".join(lines)
    )
    # Fixture should have been rewritten by the stub builder (proves regen ran).
    after = stress.read_text(encoding="utf-8")
    assert after != before, "drift mode stub must alter the stress fixture"

    assert proc.returncode != 0, (
        "expected nonzero exit when regenerated stress fixture differs from tracked fixture "
        "(fail before eval comparison is trustworthy)\\n"
        f"stdout:\\n{proc.stdout}\\nstderr:\\n{proc.stderr}\\nlog:\\n" + "\\n".join(lines)
    )
    # Must not reach evaluator outputs after drift (fail closed early).
    assert not _eval_gates(log_path), (
        "fixture drift must abort before run_eval; got evals: " + str(_eval_gates(log_path))
    )


def test_shell_bar_checks_every_evaluator_output(tmp_path: Path):
    """bar_check_v11.py must be invoked for each /tmp/v12-gate-*.json evaluator artifact."""
    root, log_path, script = _build_sandbox(tmp_path, mode="clean")
    proc = _run_shell(script, root)
    lines = _log_lines(log_path)
    bar_paths = _bar_paths(log_path)
    eval_gates = _eval_gates(log_path)

    assert set(eval_gates) == set(EVAL_GATES), (
        f"expected evals for {EVAL_GATES}, got {eval_gates}\\nlog:\\n" + "\\n".join(lines)
    )

    expected_paths = {f"/tmp/v12-gate-{g}.json" for g in EVAL_GATES}
    got_paths = set(bar_paths)
    missing = expected_paths - got_paths
    assert not missing, (
        "expected production seam: bar_check every evaluator output "
        f"(missing {sorted(missing)}); current shell may only check heldout-v11r5 or swallow errors.\\n"
        f"exit={proc.returncode}\\nbar_paths={bar_paths}\\nlog:\\n" + "\\n".join(lines)
    )


def test_shell_exits_nonzero_when_any_bar_check_fails(tmp_path: Path):
    """A failed bar_check must make the shell exit nonzero (no `|| echo` catch-and-continue)."""
    root, log_path, script = _build_sandbox(tmp_path, mode="bar_fail")
    proc = _run_shell(script, root)
    lines = _log_lines(log_path)
    bar_paths = _bar_paths(log_path)

    assert bar_paths, (
        "bar_check never invoked; cannot prove fail-closed propagation\\n"
        f"exit={proc.returncode}\\nstdout:\\n{proc.stdout}\\nstderr:\\n{proc.stderr}\\nlog:\\n"
        + "\\n".join(lines)
    )
    assert proc.returncode != 0, (
        "expected production seam: remove `bar_check ... || echo ...` so set -euo pipefail "
        "propagates bar failure as nonzero shell status.\\n"
        f"exit={proc.returncode}\\nstdout:\\n{proc.stdout}\\nstderr:\\n{proc.stderr}\\nlog:\\n"
        + "\\n".join(lines)
    )


def test_expected_production_seams_are_documented():
    """Guard: this module's docstring still names the exact shell seams implementers must add."""
    doc = Path(__file__).read_text(encoding="utf-8")
    for needle in (
        "build_stress_heldout.py",
        "bar_check_v11.py",
        "set -euo pipefail",
        "stress_orgaddr_heldout.jsonl",
        "catch-and-continue",
    ):
        assert needle in doc, f"contract doc missing {needle!r}"
