"""Rule catalog for --check-training-log. Ids, severities and texts live here so `--explain` and docs/RULES.md read the same data."""
from __future__ import annotations

from dataclasses import dataclass

from checksnap.core import Severity


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: Severity
    title: str
    explanation: str
    fix_hint: str
    needs_snap: bool = False


L, M, H = Severity.LOW, Severity.MEDIUM, Severity.HIGH

_R = [
    ("TL-001", H, "NaN or inf in a logged metric",
     "A metric became NaN or infinite. Once a weight or activation is NaN every later step is garbage, so the run after this line is wasted compute.",
     "Lower the learning rate, add gradient clipping, check for log(0)/division by zero, use bf16 or loss scaling, and resume from the last checkpoint before the first bad line."),
    ("TL-002", M, "Training loss spike",
     "The training loss jumped to more than 3x the median of the preceding steps. Spikes usually mean a bad batch, a too-high learning rate or an unstable optimizer state, and often leave the model worse for a long time.",
     "Inspect the batch at that step, clip gradients, lower the peak learning rate or lengthen warmup, and filter corrupt samples."),
    ("TL-003", L, "Training loss has plateaued",
     "The best training loss in the last quarter of the log is not meaningfully better (< 0.1%) than the best before it: learning has stalled.",
     "Check the learning rate (too low or decayed to nothing), the optimizer, frozen layers or detached graphs; stop early if the run has converged."),
    ("TL-004", M, "Train/validation gap is widening",
     "The validation-minus-training loss gap in the last third of the run is more than twice the gap in the first third: a classic sign of growing overfitting.",
     "Add regularization or augmentation, get more data, reduce capacity, or stop at the epoch with the smallest gap."),
    ("TL-005", M, "Validation loss rising while training loss falls",
     "Over the last third of the run validation loss increased while training loss decreased: the model is memorizing the training set.",
     "Use the checkpoint with the best validation loss (early stopping), add regularization, or check for a train/validation split problem."),
    ("TL-006", L, "Learning-rate schedule oddity",
     "The logged learning rate is negative, zero before the end of the run, or jumps up by 10x or more after warmup. This is rarely intended and often a scheduler bug (wrong step unit, resumed scheduler state lost).",
     "Print the scheduler on a dry run, check the step unit (per step vs per epoch), and restore scheduler state when resuming."),
    ("TL-007", H, "Gradient-norm explosion",
     "The gradient norm exceeded 10x its median and 5 absolute: the optimizer took a step far larger than usual, which typically precedes loss spikes or NaNs.",
     "Enable gradient clipping (clip_grad_norm_), lower the learning rate, check normalization layers and the data at that step."),
    ("TL-008", L, "Epoch/step time regression",
     "The median time per epoch or step in the last third of the run is more than 1.5x that of the first third. Typical causes are a leaking Python structure, growing logging, thermal throttling, or dataloader starvation.",
     "Profile a late step against an early one; look for growing lists/tensors kept across steps, disk or network contention, and GPU clocks."),
    ("TL-009", M, "GPU memory growth",
     "Logged GPU memory rises steadily (at least 20% from the first to the last third, almost never decreasing). This is the signature of a leak, such as storing tensors with their graph attached, and ends in an out-of-memory crash.",
     "Detach tensors you keep (`loss.item()`, `.detach().cpu()`), clear caches deliberately, and look for lists that accumulate per step."),
    ("TL-010", M, "Duplicated epochs/steps (resume overlap)",
     "The same epoch or step is logged more than once with the same metrics. After a resume from an older checkpoint or an appended log this double-counts progress and corrupts curves and averages.",
     "Truncate the log at the resume point or log the resume step; deduplicate by (run id, step) before plotting."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _R}
