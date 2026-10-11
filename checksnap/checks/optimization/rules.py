"""Rule catalog for the static layer. One place for ids, severities and texts so `--explain` and docs/RULES.md
read the same data the analyzers use."""
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

_STATIC = [
    ("OPT-PY-001", M, "String rebuilt by concatenation in a loop",
     "Strings are immutable: `s += x` or `s = s + x` copies the whole string each iteration, so the loop is quadratic in output size. "
     "The same applies to `lst = lst + [x]` (a list `+=` extends in place and is fine).",
     "Collect parts in a list and `''.join(parts)` once; use `lst.append` / `lst.extend`."),
    ("OPT-PY-002", M, "Regular expression with a constant pattern used inside a loop",
     "`re.compile` in a loop recompiles every time; `re.match/search/sub/...` with a constant pattern pays a cache lookup per call "
     "and hides that the pattern never changes.",
     "Hoist `PATTERN = re.compile(...)` to module level and call `PATTERN.match(...)` in the loop."),
    ("OPT-PY-003", M, "Membership test against a list inside a loop",
     "`x in some_list` scans the list, O(n) per test, so the loop is O(n*m). A set or dict answers in O(1).",
     "Build `set(some_list)` once before the loop (when the items are hashable)."),
    ("OPT-PY-004", L, "`for i in range(len(x))` index loop",
     "Index loops are slower than direct iteration and invite off-by-one errors.",
     "Use `for item in x`, `enumerate(x)` or `zip(a, b)`."),
    ("OPT-PY-005", M, "Loop-invariant file opened or read on every iteration",
     "Opening and reading the same path each iteration repeats system calls and parsing for identical data.",
     "Read the file once before the loop and reuse the content."),
    ("OPT-PY-006", M, "Sort inside a loop",
     "Sorting a loop-invariant (or incrementally grown) collection on every iteration costs O(n log n) per pass.",
     "Sort once after the loop, or keep it ordered with `bisect.insort` / `heapq`."),
    ("OPT-PY-007", H, "Blocking call inside `async def`",
     "`time.sleep`, `requests.*`, `urlopen` and `subprocess.run` block the event loop, freezing every other task while they wait.",
     "Use `await asyncio.sleep`, an async client (httpx.AsyncClient, aiohttp), `asyncio.create_subprocess_exec`, or `asyncio.to_thread`."),
    ("OPT-PY-008", H, "Database query inside a loop (N+1)",
     "One `execute` per item costs one round trip per item; latency multiplies by the number of items.",
     "Fetch everything in one query (`WHERE id IN (...)`, a JOIN) or use `executemany` for writes."),
    ("OPT-PY-009", M, "pandas `iterrows()` / `apply(axis=1)`",
     "Both run a Python-level function per row and build a Series per row; typically 10-1000x slower than vectorized operations.",
     "Use vectorized column arithmetic, `np.where`, `merge`, or `itertuples()` if a loop is unavoidable."),
    ("OPT-PY-010", M, "Same JSON/pickle/YAML file parsed in every iteration",
     "`json.load(open(path))` with a path that does not change inside the loop re-reads and re-parses identical data.",
     "Load once before the loop."),
    ("OPT-PY-011", M, "`lru_cache(maxsize=None)` / `cache` on a method",
     "The cache is keyed on `self`, so it holds a strong reference to every instance ever used and never evicts: a memory leak.",
     "Cache a module-level function keyed on the needed arguments, or use a bounded `maxsize`, or store the cache on the instance."),
    ("OPT-PY-012", L, "`list(...)` copy wrapped in sum/any/all/min/max",
     "These builtins accept any iterable; materializing a list first allocates memory and defeats short-circuiting of any/all.",
     "Pass the generator or iterable directly: `any(f(x) for x in xs)`."),
    ("OPT-PY-013", L, "`list.pop(0)` / `list.insert(0, x)` in a loop",
     "Both shift every element, so the loop is quadratic.",
     "Use `collections.deque` (`popleft`, `appendleft`) or iterate with an index."),
    ("OPT-ML-001", M, "Host synchronization inside a training loop",
     "`.item()`, `.cpu()`, `.numpy()` and `float(tensor)` wait for the GPU to finish all queued work, stalling the pipeline every step.",
     "Accumulate on the device (`running += loss.detach()`) and sync only every N steps or at epoch end."),
    ("OPT-ML-002", M, "DataLoader without worker / pinned-memory settings",
     "`num_workers=0` loads data in the training process, starving the GPU; without `pin_memory=True` host-to-device copies cannot overlap; "
     "without `persistent_workers=True` workers restart every epoch.",
     "Set `num_workers` (4-8), `pin_memory=True` and `persistent_workers=True` (needs num_workers > 0)."),
    ("OPT-ML-003", M, "Training loop without mixed precision",
     "No `torch.autocast` / AMP found in a file with a training loop; fp32-only training leaves tensor-core throughput and memory on the table.",
     "Wrap the forward pass in `torch.autocast(device_type, dtype=torch.bfloat16)` (plus GradScaler for fp16)."),
    ("OPT-ML-004", M, "Evaluation code without `torch.no_grad()` / `inference_mode()`",
     "Without it autograd records a graph for every forward pass, wasting memory and time.",
     "Decorate with `@torch.inference_mode()` or wrap the loop in `with torch.no_grad():`."),
    ("OPT-ML-005", M, "Python loop over tensor elements",
     "Iterating elements of a tensor in Python runs one tiny op per element (and a sync on GPU); vectorized ops are orders of magnitude faster.",
     "Express the computation with tensor operations, `torch.where`, `index_select`, or batched matmul."),
    ("OPT-ML-006", L, "Tensor created on CPU every step, then moved to the device",
     "`torch.zeros(...).to(device)` allocates on the host and copies each step.",
     "Create directly on the device: `torch.zeros(..., device=device)`, or hoist the constant out of the loop."),
    ("OPT-ML-007", L, "`.to(device)` without `non_blocking=True` while using pinned memory",
     "With `pin_memory=True` the copy can be asynchronous, but only if `non_blocking=True` is passed.",
     "Use `batch.to(device, non_blocking=True)`."),
    ("OPT-ML-008", M, "`torch.cuda.synchronize()` inside a loop",
     "Forces the CPU to wait for the GPU every iteration, destroying asynchronous overlap. It belongs in benchmark timing only.",
     "Remove it, or synchronize once around the timed region."),
    ("OPT-ML-009", M, "Checkpoint saved on every step",
     "Serializing model and optimizer state every iteration makes I/O dominate training time.",
     "Guard with `if step % N == 0` or save once per epoch / on best validation score."),
    ("OPT-ML-010", L, "`optimizer.zero_grad()` without `set_to_none=True`",
     "Setting grads to zero writes memory each step; `set_to_none=True` skips that and lets the allocator reuse buffers (default only since PyTorch 2.0).",
     "Call `optimizer.zero_grad(set_to_none=True)`."),
    ("OPT-ML-011", M, "Depthwise / grouped convolution (AMD ROCm slow path)",
     "`groups=in_channels` convolutions hit a very slow kernel on AMD RDNA3/ROCm (measured about 500x slower than dense on a 7900 XT) and are memory-bound on many GPUs. "
     "A dense conv with more FLOPs can still be much faster in wall-clock time.",
     "Benchmark a dense conv (groups=1) on the target hardware; keep depthwise only if measured faster."),
    ("OPT-ML-012", L, "`cudnn.benchmark = True` with dynamic input shapes",
     "cuDNN autotunes per input shape; variable shapes retrigger the autotuner constantly, which is slower than leaving it off.",
     "Enable it only for fixed shapes, or pad / bucket inputs to a few sizes."),
    ("OPT-ML-013", M, "float64 tensors created from numpy / explicit double",
     "numpy defaults to float64; `torch.from_numpy(np.zeros(...))` yields a double tensor that is 2x memory and far slower on most GPUs.",
     "Pass `dtype=np.float32` / `torch.float32`, or call `.float()` once on load."),
]

STATIC_RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _STATIC}
