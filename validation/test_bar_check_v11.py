"""Hermetic CLI tests for validation/bar_check_v11.py exit semantics.

Exercises the real script process (not only check()) with synthetic
eval_labelaware-shaped JSON so ship-bar failures and missing inputs cannot
silently exit zero. Model-free; fixtures live only in temp directories.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TRAINING_DIR = REPO / "training"
sys.path.insert(0, str(TRAINING_DIR))
from metrics_contract import SHIP_FLOOR_LABELS
SCRIPT = REPO / "validation" / "bar_check_v11.py"


# Operational labels that still must clear the global F1 floor.
OPERATIONAL_LABELS = ("organization", "address")


def _label_row(
    *,
    gold: int = 100,
    recall_labeled: float = 1.0,
    precision: float = 0.99,
    f1: float = 0.995,
    pred: int | None = None,
) -> dict:
    if pred is None:
        pred = gold
    return {
        "gold": gold,
        "recall_labeled": recall_labeled,
        "recall_detect": recall_labeled,
        "precision": precision,
        "f1": f1,
        "fp": 0,
        "wrong_label": 0,
        "pred": pred,
    }


def _synthetic_eval(
    *,
    overall_recall: float = 0.99,
    overall_precision: float = 0.96,
    cat_recall: float = 1.0,
    cat_precision: float = 0.99,
    cat_f1: float = 0.995,
    op_f1: float = 0.98,
    fail_label: str | None = None,
    fail_recall: float = 0.50,
) -> dict:
    """Build a minimal model-alone evaluator payload that satisfies bar_check_v11 keys."""
    per_label: dict[str, dict] = {}
    for lab in sorted(SHIP_FLOOR_LABELS):
        if lab == fail_label:
            # F1 deliberately below 0.93 so the threshold failure is unambiguous.
            per_label[lab] = _label_row(
                recall_labeled=fail_recall,
                precision=0.99,
                f1=0.66,
            )
        else:
            per_label[lab] = _label_row(
                recall_labeled=cat_recall,
                precision=cat_precision,
                f1=cat_f1,
            )
    for lab in OPERATIONAL_LABELS:
        per_label[lab] = _label_row(
            recall_labeled=0.98,
            precision=0.98,
            f1=op_f1,
        )
    return {
        "model": "synthetic-bar-check-fixture",
        "n_rows": 32,
        "modes": {
            "model": {
                "labeled_recall": overall_recall,
                "detect_recall": overall_recall,
                "precision": overall_precision,
                "f1": 0.97,
                "clean_fp": 0,
                "neg_rows": 0,
                "per_label": per_label,
            }
        },
    }


def _write_eval(tmp_path: Path, payload: dict, name: str = "eval.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run_bar_check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env={**os.environ, "PYTHONPATH": str(REPO)},
        check=False,
    )


def test_all_pass_exits_zero_with_pass_verdict(tmp_path: Path) -> None:
    eval_path = _write_eval(tmp_path, _synthetic_eval())
    result = _run_bar_check(str(eval_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERDICT: *** PASS ***" in result.stdout
    assert ": PASS" in result.stdout.split("SUMMARY:")[-1]


def test_threshold_failure_exits_nonzero_with_fail_verdict(tmp_path: Path) -> None:
    # One catastrophic label under the strict recall floor; overall metrics remain clean.
    eval_path = _write_eval(
        tmp_path,
        _synthetic_eval(fail_label="government_id", fail_recall=0.50),
    )
    result = _run_bar_check(str(eval_path))
    assert result.returncode != 0, (
        "bar_check_v11 must exit nonzero when a ship-floor criterion fails; "
        f"got rc=0\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "VERDICT: FAIL" in result.stdout
    assert "government_id" in result.stdout
    assert "PASS" not in result.stdout.split("SUMMARY:")[-1]


def test_no_input_exits_nonzero_with_usage_failure() -> None:
    result = _run_bar_check()
    assert result.returncode != 0, (
        "bar_check_v11 must exit nonzero when no evaluator JSON is supplied; "
        f"got rc=0\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    combined = (result.stdout + result.stderr).lower()
    assert (
        "usage" in combined
        or "eval.json" in combined
        or "no input" in combined
        or "required" in combined
        or "argument" in combined
        or "missing" in combined
    ), f"expected a usage/missing-input message, got:\n{result.stdout}\n{result.stderr}"
