"""Every TL rule: one log that must trigger it, one clean log that must not. Plus parser formats and the CLI-facing check."""
from __future__ import annotations

import argparse
import json
import math

import pytest

from checksnap.checks.traininglog import RULES, TrainingLogCheck
from checksnap.checks.traininglog.analyze import analyze
from checksnap.checks.traininglog.parse import parse_text
from checksnap.core import Context, REGISTRY


def rows(n=30, **fn):
    """n epochs; each kwarg is a function epoch->value."""
    return [{"epoch": i, **{k: f(i) for k, f in fn.items()}} for i in range(n)]


def ids(rs):
    return {f.rule_id for f in analyze(parse_text("\n".join(json.dumps(r) for r in rs), ".jsonl"), "x.jsonl")}


HEALTHY = dict(loss=lambda i: 2 * math.exp(-i / 8) + 0.1, val_loss=lambda i: 2 * math.exp(-i / 8) + 0.15, lr=lambda i: 1e-3 * (1 - i / 31),
               grad_norm=lambda i: 1.0, epoch_time=lambda i: 10.0, gpu_mem=lambda i: 5000.0)


def test_healthy_log_is_clean():
    assert ids(rows(**HEALTHY)) == set()


def test_registry_and_catalog():
    assert REGISTRY["traininglog"].flag == "--check-training-log"
    assert len(RULES) == 10 and all(r.fix_hint and r.explanation for r in RULES.values())


def test_tl001_nan_inf():
    r = rows(**HEALTHY)
    r[5]["loss"] = "nan"
    assert "TL-001" in ids(r)
    r = rows(**HEALTHY)
    r[5]["val_loss"] = float("inf")
    assert "TL-001" in ids(r)


def test_tl002_spike():
    h = dict(HEALTHY, loss=lambda i: 5.0 if i == 20 else 0.5)
    assert "TL-002" in ids(rows(**h))
    assert "TL-002" not in ids(rows(**HEALTHY))


def test_tl003_plateau():
    h = dict(HEALTHY, loss=lambda i: 1.0 / (i + 1) if i < 10 else 0.1)
    assert "TL-003" in ids(rows(**h))
    assert "TL-003" not in ids(rows(**HEALTHY))


def test_tl004_gap_widening():
    h = dict(HEALTHY, val_loss=lambda i: HEALTHY["loss"](i) + 0.01 + 0.05 * i)
    assert "TL-004" in ids(rows(**h))
    assert "TL-004" not in ids(rows(**HEALTHY))


def test_tl005_val_rising_train_falling():
    h = dict(HEALTHY, val_loss=lambda i: 0.5 + 0.02 * abs(i - 10) if i > 10 else 1.0 - 0.05 * i)
    assert "TL-005" in ids(rows(**h))
    assert "TL-005" not in ids(rows(**HEALTHY))


def test_tl006_lr_oddities():
    assert "TL-006" in ids(rows(**dict(HEALTHY, lr=lambda i: 1e-4 if i < 15 else 1e-2)))      # 100x jump after warmup
    assert "TL-006" in ids(rows(**dict(HEALTHY, lr=lambda i: 0.0 if i == 10 else 1e-3)))      # zero mid-run
    assert "TL-006" not in ids(rows(**dict(HEALTHY, lr=lambda i: 1e-3 * min(1, (i + 1) / 5))))  # warmup is fine
    assert "TL-006" not in ids(rows(**dict(HEALTHY, lr=lambda i: 0.0 if i == 29 else 1e-3)))    # zero at the very end is fine


def test_tl007_grad_explosion():
    assert "TL-007" in ids(rows(**dict(HEALTHY, grad_norm=lambda i: 500.0 if i == 12 else 1.0)))
    assert "TL-007" not in ids(rows(**dict(HEALTHY, grad_norm=lambda i: 0.01 if i != 12 else 0.2)))   # 20x but tiny in absolute terms


def test_tl008_epoch_time():
    assert "TL-008" in ids(rows(**dict(HEALTHY, epoch_time=lambda i: 10.0 + 2 * i)))
    assert "TL-008" not in ids(rows(**HEALTHY))


def test_tl009_gpu_memory_growth():
    assert "TL-009" in ids(rows(**dict(HEALTHY, gpu_mem=lambda i: 5000.0 + 100 * i)))
    assert "TL-009" not in ids(rows(**dict(HEALTHY, gpu_mem=lambda i: 5000.0 + 100 * (i % 3))))


def test_tl010_duplicate_epochs_after_resume():
    r = rows(10, loss=lambda i: 1.0 / (i + 1))
    assert "TL-010" in ids(r + r[5:])
    assert "TL-010" not in ids(r)
    # train and val logged on separate lines for the same epoch is NOT a duplicate (wandb style)
    split = [x for i in range(10) for x in ({"epoch": i, "loss": 1.0 / (i + 1)}, {"epoch": i, "val_loss": 1.1 / (i + 1)})]
    assert "TL-010" not in ids(split)


def test_tl010_uses_step_when_present():
    r = [{"step": i, "epoch": 0, "loss": 1.0 / (i + 1)} for i in range(10)]
    assert "TL-010" not in ids(r)
    assert "TL-010" in ids(r + r[7:])


def test_parse_text_lines():
    recs = parse_text("epoch 3 loss 0.41 val_loss 0.52\nEpoch 4/10 - loss: 1e-2 - val_loss: nan\nhello world\n", ".log")
    assert recs[0].vals == {"epoch": 3, "loss": 0.41, "val_loss": 0.52}
    assert recs[1].vals["epoch"] == 4 and math.isnan(recs[1].vals["val_loss"])


def test_parse_csv_and_wandb_nested_and_keras_json():
    assert parse_text("epoch,loss\n1,0.5\n2,0.4\n", ".csv")[1].vals == {"epoch": 2, "loss": 0.4}
    assert parse_text('{"_step": 1, "train": {"loss": 0.5}}\n', ".jsonl")[0].vals == {"_step": 1, "train/loss": 0.5}
    assert [r.vals for r in parse_text('{"loss": [1.0, 0.5], "val_loss": [1.1, 0.7]}', ".json")][1] == {"loss": 0.5, "val_loss": 0.7}


def test_check_end_to_end(tmp_path):
    r = rows(**dict(HEALTHY, loss=lambda i: float("nan") if i == 4 else 1.0))
    (tmp_path / "run.jsonl").write_text("\n".join(json.dumps(x) for x in r))
    (tmp_path / "notes.txt").write_text("nothing here\n")
    chk = TrainingLogCheck()
    ns = argparse.Namespace(check_training_log=str(tmp_path))
    ctx = Context(no_snap=True)
    assert chk.estimate(ctx, ns).snap_calls == 0
    res = chk.run(ctx, ns)
    assert res.error is None and res.findings[0].rule_id == "TL-001" and res.findings[0].evidence[0].file == "run.jsonl"
    assert chk.run(ctx, argparse.Namespace(check_training_log=str(tmp_path / "nope"))).error
