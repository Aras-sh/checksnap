"""Rule catalog for --check-reproducibility. Ids, severities and texts live here so `--explain` and docs read one source."""
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

_SEED_FIX = "Call one seed function at program start, e.g. `random.seed(s); np.random.seed(s); torch.manual_seed(s)`, and log `s`."
_RULES = [
    ("REP-001", M, "Python `random` used but never seeded",
     "The `random` module is used and no `random.seed(...)` (or a seed_everything-style helper) exists in the project, so every run draws different numbers.", _SEED_FIX),
    ("REP-002", M, "NumPy randomness used but never seeded",
     "`np.random.*` global functions are used and no `np.random.seed(...)` / seeded `default_rng(seed)` / `RandomState(seed)` exists in the project.",
     "Seed once (`np.random.seed(s)`) or, better, pass an explicit `np.random.default_rng(s)` around."),
    ("REP-003", M, "PyTorch randomness used but never seeded",
     "torch random ops, layer initialisation, dropout or a shuffling DataLoader are used and `torch.manual_seed` is never called, so weights, dropout masks and batch order differ per run.",
     "Call `torch.manual_seed(s)` (it also seeds CUDA) at start."),
    ("REP-004", M, "TensorFlow/Keras randomness used but never seeded",
     "`tf.random.*` or Keras layers are used and no `tf.random.set_seed` / `keras.utils.set_random_seed` exists.",
     "Call `tf.keras.utils.set_random_seed(s)` (seeds python, numpy and TF together)."),
    ("REP-005", M, "Seed is set after the random source was already used",
     "In the same scope a random call runs before the seed call, so the first draws (often data splits or weight init) are not reproducible even though a seed exists.",
     "Move the seed call above every use, to the very top of `main()` / the module."),
    ("REP-006", L, "cudnn.benchmark enabled or cudnn.deterministic disabled",
     "`torch.backends.cudnn.benchmark = True` lets cuDNN pick algorithms by timing, which can differ between runs; `deterministic = False` allows non-deterministic kernels explicitly.",
     "Set `cudnn.benchmark = False` and `cudnn.deterministic = True` when reproducibility matters (costs some speed)."),
    ("REP-007", L, "PyTorch project never requests deterministic cuDNN",
     "torch randomness is used but nothing sets `torch.backends.cudnn.deterministic = True` or calls `torch.use_deterministic_algorithms`; GPU convolutions can then vary run to run even with a fixed seed.",
     "Add `torch.backends.cudnn.deterministic = True; torch.backends.cudnn.benchmark = False`."),
    ("REP-008", M, "DataLoader without worker_init_fn / generator",
     "A DataLoader that shuffles or uses worker processes but has neither `generator=` nor `worker_init_fn=` leaves shuffling order and per-worker numpy/random state unseeded.",
     "Pass `generator=torch.Generator().manual_seed(s)` and a `worker_init_fn` that seeds numpy/random from `torch.initial_seed()`."),
    ("REP-009", M, "Directory listing / glob used without sorting",
     "`os.listdir`, `os.scandir`, `glob.glob`, `Path.glob/rglob/iterdir` return files in filesystem order, which differs between machines; data order and splits built from it change.",
     "Wrap in `sorted(...)`."),
    ("REP-010", M, "Iteration over a set",
     "Set iteration order depends on hash values; for strings it changes between processes (PYTHONHASHSEED), so anything built in that order (data lists, vocabularies, splits) is not reproducible.",
     "Iterate `sorted(the_set)` or keep an ordered structure (dict / list with de-duplication)."),
    ("REP-011", L, "Reliance on hash or unordered-container order",
     "`hash()` of str/bytes is salted per process, `dict.popitem()` depends on insertion history and `set.pop()` / `next(iter(set))` returns an arbitrary element.",
     "Use `hashlib` for stable hashes; pick elements explicitly (`min(s)`, `sorted(s)[0]`)."),
    ("REP-012", M, "Wall-clock time used in a path or result name",
     "`datetime.now()` / `time.time()` formatted into a directory, file or run name means each run writes somewhere different and results cannot be located or diffed by configuration.",
     "Derive run names from config + seed (or a git hash); record the timestamp inside the metadata instead."),
    ("REP-013", M, "Unpinned dependencies",
     "Requirements without `==` resolve to whatever is newest at install time, so the same code can behave differently next month.",
     "Pin exact versions (`pip freeze`, `pip-compile`, `uv lock`)."),
    ("REP-014", M, "Third-party imports but no dependency manifest",
     "The code imports third-party packages yet there is no requirements.txt, pyproject.toml, environment.yml, Pipfile or setup.py, so nobody can rebuild the environment.",
     "Add a requirements.txt or pyproject.toml, preferably with pinned versions."),
    ("REP-015", L, "No lockfile or fully pinned requirements",
     "A manifest exists but no lock file (poetry.lock, uv.lock, Pipfile.lock, pdm.lock, conda-lock.yml) and no fully pinned requirements file, so transitive dependencies float.",
     "Commit a lock file or a `pip freeze` / `pip-compile` output."),
    ("REP-016", L, "ML code never records the git commit",
     "Training/ML code that does not log the git commit (rev-parse, GitPython, wandb/mlflow/dvc...) makes it impossible to tell which code produced a result.",
     "Save `git rev-parse HEAD` (and whether the tree was dirty) next to every result."),
    ("REP-017", L, "ML code never saves its config / hyperparameters",
     "No sign of the run configuration being written out (`vars(args)` dump, OmegaConf.save, hparams, wandb/mlflow config...), so results cannot be tied to settings.",
     "Dump the full resolved config (including seed) to the output directory at start."),
    ("REP-018", M, "Non-deterministic CUDA op without use_deterministic_algorithms",
     "`index_add_`, `scatter_`, `scatter_add_`, `index_put_(accumulate=True)`, `bincount` and similar use atomic adds on CUDA, so float results vary run to run unless `torch.use_deterministic_algorithms(True)` is set.",
     "Call `torch.use_deterministic_algorithms(True)` (set CUBLAS_WORKSPACE_CONFIG=:4096:8) or use a deterministic formulation."),
]

RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
