"""Rule catalog for --check-repo: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
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


I, L, M, H = Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH

_R = [
    ("REPO-001", H, "Large file (over 50 MB) not covered by .gitignore",
     "Git stores every version of a file forever; one big blob makes every clone slow and hosts like GitHub reject pushes above 100 MB.",
     "Add it to .gitignore, or track it with Git LFS / DVC and keep only a pointer in the repo."),
    ("REPO-002", M, "Model or data artifact not covered by .gitignore",
     "Checkpoints and data dumps (.pt, .ckpt, .safetensors, .h5, .npy, .parquet, .zip ...) are large, binary and change often, so they bloat history.",
     "Ignore the file or its directory, and distribute it through a release, object store, Git LFS or DVC."),
    ("REPO-003", M, "No .gitignore",
     "Without one, caches, virtualenvs, secrets and build output are one `git add .` away from being committed.",
     "Add a .gitignore (for Python: __pycache__/, .venv/, .env, runs/, data/)."),
    ("REPO-004", L, "Common paths present but not ignored",
     "__pycache__, .env, .venv, runs/ or data/ exist in the tree and no .gitignore rule covers them.",
     "Add the listed entries to .gitignore."),
    ("REPO-005", H, "Secrets file in the tree and not ignored",
     "Files such as .env, id_rsa, *.pem or credentials.json hold credentials; once committed they stay in history even after deletion.",
     "Ignore the file, rotate the credential if it was ever committed, and ship a .env.example instead."),
    ("REPO-006", L, "No README", "A README is the first thing a reader looks for: what this is, how to run it.", "Add README.md."),
    ("REPO-007", I, "No LICENSE", "Without a license, nobody else may legally reuse the code.", "Add a LICENSE file (see choosealicense.com)."),
    ("REPO-008", M, "Jupyter notebook with large saved outputs",
     "Embedded images and tables make notebooks huge, produce unreadable diffs and leak whatever the cells printed.",
     "Clear outputs before committing (`jupyter nbconvert --clear-output --inplace`, or nbstripout as a git filter)."),
    ("REPO-009", L, "Broken symlink", "The link points at a target that does not exist, so tools that follow it fail.", "Remove it or fix its target."),
    ("REPO-010", L, "Duplicate files (identical content)",
     "Identical copies waste space and drift apart when only one is edited.", "Keep one copy and reference it (import, symlink, config path)."),
    ("REPO-011", M, "Filenames that differ only by case",
     "On case-insensitive filesystems (macOS, Windows) these collide and one silently overwrites the other at checkout.", "Rename one of them."),
    ("REPO-012", L, "Very long path (over 200 characters)",
     "Windows tools historically fail above 260 characters, and checkouts under a deep directory push paths over that limit.", "Shorten directory or file names."),
    ("REPO-013", L, "Mixed CRLF and LF line endings in one file",
     "Mixed endings cause whole-file diffs, noisy blame and shell scripts that fail with `\\r: command not found`.",
     "Normalize to LF and add a .gitattributes with `* text=auto`."),
    ("REPO-014", H, "Leftover merge-conflict markers",
     "`<<<<<<<` / `>>>>>>>` blocks mean a merge was committed unresolved; the file is probably broken.", "Resolve the conflict and remove the markers."),
    ("REPO-015", I, "TODO / FIXME comments", "Counts open markers so the number can be tracked; not a defect by itself.", "Turn important ones into issues."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _R}
