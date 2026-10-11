"""--check-dataset: contamination, duplicates, leaks, PII, hygiene, licences and image checks.

Local analysis always runs; Snap (long-context model) adds paraphrase-proof contamination and a licence question."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from checksnap.core import Check, CheckResult, Context, CostEstimate, Finding, register

from . import snapcheck
from .analyzers import Hygiene, License, LocalContam, Pii, dup_findings, leak_findings
from .records import IMG_EXT, TEXT_EXT, Rec, file_id, iter_records, list_files, load_benchmarks, rel
from .rules import RULES, RuleInfo
from .textutil import DupIndex, Ref

__all__ = ["RULES", "RuleInfo", "DatasetCheck"]


@register
class DatasetCheck(Check):
    name = "dataset"
    flag = "--check-dataset"
    summary = "Benchmark contamination, duplicates, eval leaks, PII, hygiene, licences, images"
    uses_snap = True

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        g = p.add_argument_group("dataset check")
        g.add_argument("--benchmark", action="append", default=[], metavar="PATH", help="benchmark JSONL (repeatable)")
        g.add_argument("--field", default="question", help="benchmark item field (default: question)")
        g.add_argument("--eval", dest="eval_path", metavar="PATH", help="eval/test split to check for leakage")
        g.add_argument("--text-field", help="record field holding the text (default: join all string values)")
        g.add_argument("--label-field")
        g.add_argument("--id-field")
        g.add_argument("--id-regex", help="regex for an id (video/channel) in file names; group 1 if present")
        g.add_argument("--source-field")
        g.add_argument("--license-field")
        g.add_argument("--allowed-licenses", help="comma separated")
        g.add_argument("--modality", choices=["auto", "text", "image"], default="auto")
        g.add_argument("--max-records", type=int)
        g.add_argument("--contam-mode", choices=["exhaustive", "prefiltered"], default="exhaustive")
        g.add_argument("--dup-threshold", type=float, default=0.8, help="near-duplicate Jaccard (default 0.8)")

    # -- helpers
    @staticmethod
    def _path(args: argparse.Namespace) -> Path:
        for attr in ("check_dataset", "check_all"):
            v = getattr(args, attr, None)
            if isinstance(v, (str, Path)):
                return Path(v)
        return Path(".")

    @staticmethod
    def _files(path: Path, modality: str) -> tuple[list[Path], list[Path]]:
        fs = list_files(path)
        text = [f for f in fs if f.suffix.lower() in TEXT_EXT] if modality != "image" else []
        imgs = [f for f in fs if f.suffix.lower() in IMG_EXT] if modality != "text" else []
        return text, imgs

    def estimate(self, ctx: Context, args: argparse.Namespace) -> CostEstimate:
        path = self._path(args)
        if ctx.no_snap or not path.exists():
            return CostEstimate()
        text, _ = self._files(path, getattr(args, "modality", "auto"))
        total = sum(f.stat().st_size for f in text)
        items = len(load_benchmarks(getattr(args, "benchmark", []) or [], getattr(args, "field", "question"), []))
        return snapcheck.estimate_cost(ctx.snap, total, items, with_license=bool(total))

    def run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        return self.timed(lambda: self._run(ctx, args))

    def _run(self, ctx: Context, args: argparse.Namespace) -> CheckResult:
        res = CheckResult(self.name)
        path = self._path(args)
        if not path.exists():
            res.error = f"path not found: {path}"
            return res
        try:
            self._analyse(ctx, args, path, res)
        except Exception as exc:  # noqa: BLE001  (a check must degrade to an error, not a traceback)
            res.error = f"{type(exc).__name__}: {exc}"
        return res

    def _analyse(self, ctx: Context, args: argparse.Namespace, path: Path, res: CheckResult) -> None:
        g = lambda k, d=None: getattr(args, k, d)  # noqa: E731
        text_files, img_files = self._files(path, g("modality", "auto"))
        field = g("field", "question")
        items = load_benchmarks(g("benchmark", []) or [], field, res.notes)
        allowed = {a.strip().lower() for a in (g("allowed_licenses") or "").split(",") if a.strip()}
        id_field, id_regex = g("id_field"), g("id_regex")
        thr = g("dup_threshold", 0.8)

        dups, pii = DupIndex(thr), Pii()
        hyg = Hygiene(g("label_field"), id_field)
        lic = License(g("license_field"), g("source_field"), allowed)
        local = LocalContam(items) if items else None
        issues: list = []
        ds_ids: set[str] = set()
        n = chars = 0
        for rec in iter_records(text_files, path, g("text_field"), g("max_records"), issues):
            n += 1
            chars += len(rec.text)
            dups.add(rec.file, rec.idx, rec.text)
            pii.feed(rec)
            hyg.feed(rec)
            lic.feed(rec)
            if local:
                local.feed(rec)
            i = (str(rec.raw[id_field]) if id_field and rec.raw and rec.raw.get(id_field) is not None else None) or file_id(rec.file, id_regex)
            if i:
                ds_ids.add(i)
        res.stats.update({"records": n, "chars": chars, "files": len(text_files), "benchmark_items": len(items)})
        unreadable = [x for x in issues if x[1] == 0]
        res.notes.extend(f"{f}: {why}" for f, _, why in unreadable)
        bad_lines = [x for x in issues if x[1] != 0]
        if not text_files and not img_files:
            res.notes.append(f"no readable data files in {path} (looked for {', '.join(sorted(TEXT_EXT | IMG_EXT))})")

        # eval split
        eval_labels: Counter[str] | None = None
        leak: list[Finding] = []
        eval_text: list[Path] = []
        eval_imgs: list[Path] = []
        ev_root = Path(g("eval_path")) if g("eval_path") else None
        if ev_root is not None:
            if not ev_root.exists():
                res.notes.append(f"--eval {ev_root}: not found")
                ev_root = None
            else:
                eval_text, eval_imgs = self._files(ev_root, g("modality", "auto"))
                ev_recs: list[Rec] = list(iter_records(eval_text, ev_root, g("text_field"), g("max_records")))
                ev_ids: dict[str, Ref] = {}
                eval_labels = Counter()
                lf = g("label_field")
                for r in ev_recs:
                    r.file = f"{ev_root.name}/{r.file}" if ev_root.is_dir() else r.file
                    i = (str(r.raw[id_field]) if id_field and r.raw and r.raw.get(id_field) is not None else None) or file_id(r.file, id_regex)
                    if i:
                        ev_ids.setdefault(i, Ref(r.file, r.idx))
                    if lf and r.raw and r.raw.get(lf) is not None:
                        eval_labels[str(r.raw[lf])] += 1
                leak = leak_findings(dups, ev_recs, ds_ids, ev_ids)
                res.stats["eval_records"] = len(ev_recs)

        res.findings += dup_findings(dups) + leak
        res.findings += (local.findings() if local else []) + pii.findings()
        res.findings += hyg.findings(eval_labels, bad_lines) + lic.findings()

        if img_files:
            from . import images
            if images.pillow_available():
                f, st = images.scan_images(img_files, path, eval_imgs, ev_root, id_regex)
                res.findings += f
                res.stats.update(st)
            else:
                res.notes.append(f"{len(img_files)} images skipped: Pillow not installed (pip install pillow)")

        self._snap(ctx, args, path, text_files, items, local, lic, res, g)
        res.findings.sort(key=lambda f: (-int(f.severity), f.rule_id))

    def _snap(self, ctx, args, path, text_files, items, local, lic, res, g) -> None:
        if ctx.no_snap or ctx.snap is None:
            res.notes.append("Snap parts skipped (DS-CONTAM-001, DS-LIC-001 Snap question): " + ("--no-snap" if ctx.no_snap else "no engine available"))
            return
        thr = ctx.threshold
        errors: list[str] = []
        if items:
            records = iter_records(text_files, path, g("text_field"), g("max_records"))
            if g("contam_mode", "exhaustive") == "prefiltered":
                records = snapcheck.prefilter(records, items)
                res.notes.append("contam-mode prefiltered: only records sharing rare words with an item were sent; paraphrases with few shared words can be missed")
            f, calib, usage = snapcheck.run_contamination(ctx.snap, records, items, local, thr, res.notes, ctx.progress, errors)
            res.findings += f
            self._add_usage(res, usage)
            if calib:
                res.stats["calibration"] = calib
                fpr = calib.get("false_positive_rate")
                res.notes.append(f"Snap calibration: decoy false-positive rate {fpr:.0%} at threshold {thr}" if fpr is not None else "Snap calibration: no decoys")
        f, usage = snapcheck.run_license(ctx.snap, lic.snap_text(), thr, res.notes, errors)
        res.findings += f
        self._add_usage(res, usage)
        if errors:
            res.error = "; ".join(dict.fromkeys(errors))

    @staticmethod
    def _add_usage(res: CheckResult, usage: dict) -> None:
        for k, v in usage.items():
            res.usage[k] = res.usage.get(k, 0) + v
