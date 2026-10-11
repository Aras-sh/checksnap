"""Benchmark checksnap against bandit/semgrep/detect-secrets/ruff/pylint/flake8/hadolint/yamllint/actionlint/sqlfluff.

Usage:  .bench-venv/bin/python benchmarks/compare/run_all.py [t1 t2 ... t6]     (default: all; t5 spends real Snap tokens)
Setup:  see RESULTS.md ("Reproduce"). Data generators: gen_secrets.py gen_perf.py gen_bank.py. Results merge into results.json.
Everything runs under `nice -n 10`, CPU only.
"""
import ast, json, os, random, re, shutil, subprocess, sys, sysconfig, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DATA, RAW, BIN = HERE / "data", HERE / "raw", HERE / "bin"
BV = ROOT / ".bench-venv" / "bin"
CSPY = ROOT / ".venv" / "bin" / "python"
RES = HERE / "results.json"
RAW.mkdir(exist_ok=True)
os.environ["PATH"] = f"{BV}:{os.environ['PATH']}"      # adapters (--with-adapters) find bandit/ruff/detect-secrets here


# ---------------------------------------------------------------- helpers
def sh(cmd, env=None, timeout=900, cwd=None):
    e = dict(os.environ, **(env or {}))
    t = time.perf_counter()
    p = subprocess.run(["nice", "-n", "10", *map(str, cmd)], capture_output=True, text=True, env=e, timeout=timeout, cwd=cwd)
    return {"rc": p.returncode, "out": p.stdout, "err": p.stderr, "s": round(time.perf_counter() - t, 2)}


def cs(args, env=None):
    """Run checksnap (static, no Snap) -> (seconds, flat findings [{rule,file,line,sev,title}], raw doc)."""
    e = {"PYTHONPATH": str(ROOT), "SUBQ_API_KEY": "", **(env or {})}
    r = sh([CSPY, "-m", "checksnap", *args, "--format", "json", "--fail-on", "none", "--no-snap"], e)
    try:
        doc = json.loads(r["out"])
    except Exception:
        return r["s"], [], {"error": (r["out"] + r["err"])[:500]}
    fl = []
    for res in doc["results"]:
        for f in res["findings"]:
            evs = f["evidence"] or [{"file": None, "line_start": None}]
            for ev in evs:
                fl.append({"rule": f["rule_id"], "file": ev["file"], "line": ev["line_start"], "sev": f["severity"], "title": f["title"],
                           "snippet": ev.get("snippet", "")})
    return r["s"], fl, doc


def name2(p):
    return "/".join(Path(p).parts[-2:]) if p else ""


def name(p):
    return Path(p).name if p else ""


def save(key, val):
    d = json.loads(RES.read_text()) if RES.exists() else {}
    d[key] = val
    RES.write_text(json.dumps(d, indent=1))


def versions():
    v = {}
    for t, args in {"bandit": ["--version"], "semgrep": ["--version"], "detect-secrets": ["--version"], "ruff": ["--version"], "pylint": ["--version"],
                    "flake8": ["--version"], "yamllint": ["--version"], "sqlfluff": ["--version"]}.items():
        v[t] = (sh([BV / t, *args])["out"].strip().splitlines() or ["?"])[0]
    v["hadolint"] = sh([BIN / "hadolint", "--version"])["out"].strip()
    v["actionlint"] = (sh([BIN / "actionlint", "-version"])["out"].strip().splitlines() or ["?"])[0]
    v["checksnap"] = cs(["--check-security", str(HERE / "gen_perf.py")])[2].get("version")
    v["python"] = sys.version.split()[0]
    return v


# ---------------------------------------------------------------- task 1
BANDIT_CLASS = {"SEC-001": {"B301", "B403", "B614", "B615"}, "SEC-002": {"B506"}, "SEC-003": {"B307", "B102"}, "SEC-004": {"B602", "B604"},
                "SEC-005": {"B605", "B602", "B607"}, "SEC-006": {"B105", "B106", "B107"}, "SEC-007": {"B306"}, "SEC-008": {"B501"},
                "SEC-009": {"B101"}, "SEC-010": {"B202"}, "SEC-011": {"B608"}, "SEC-012": {"B201"}, "SEC-013": {"B104"},
                "SEC-014": {"B303", "B324"}, "SEC-015": {"B103"}}
# bandit example file -> checksnap rule that is *designed* to cover it (hand labelled; unmapped files are out of checksnap's 15-rule scope)
IN_SCOPE = {"eval.py": "SEC-003", "exec.py": "SEC-003", "pickle_deserialize.py": "SEC-001", "pytorch_load.py": "SEC-001", "yaml_load.py": "SEC-002",
            "flask_debug.py": "SEC-012", "subprocess_shell.py": "SEC-004", "os_system.py": "SEC-005", "os-popen.py": "SEC-005",
            "crypto-md5.py": "SEC-014", "hashlib_new_insecure_functions.py": "SEC-014", "mktemp.py": "SEC-007",
            "hardcoded-passwords.py": "SEC-006", "requests-ssl-verify-disabled.py": "SEC-008", "assert.py": "SEC-009",
            "tarfile_extractall.py": "SEC-010", "sql_statements.py": "SEC-011", "django_sql_injection_raw.py": "SEC-011",
            "binding.py": "SEC-013", "os-chmod.py": "SEC-015"}


def bandit_gt():
    tree = ast.parse((DATA / "bandit/tests/functional/test_functional.py").read_text())
    gt = {}
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")):
            continue
        env = {}
        for st in fn.body:
            if isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Name) and isinstance(st.value, ast.Dict):
                try: env[st.targets[0].id] = ast.literal_eval(st.value)
                except Exception: pass
            for c in ast.walk(st):
                if isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "check_example" and len(c.args) >= 2 and isinstance(c.args[0], ast.Constant):
                    if any(k.arg == "ignore_nosec" for k in c.keywords):
                        continue
                    a = c.args[1]
                    try: exp = env[a.id] if isinstance(a, ast.Name) else ast.literal_eval(a)
                    except Exception: continue
                    gt[c.args[0].value] = max(gt.get(c.args[0].value, 0), sum(exp["SEVERITY"].values()))
    return gt


def task1():
    gt = {f: n for f, n in bandit_gt().items() if "/" not in f and (DATA / "bandit/examples" / f).exists()}
    ex = DATA / "t1/cases"; std = DATA / "t1/stdlib"
    shutil.rmtree(DATA / "t1", ignore_errors=True); ex.mkdir(parents=True); std.mkdir(parents=True)
    for f in gt:
        shutil.copy(DATA / "bandit/examples" / f, ex / f)
    lib = Path(sysconfig.get_paths()["stdlib"])
    skip = ("test", "idlelib", "lib2to3", "site-packages", "turtledemo", "__pycache__", "tkinter", "ensurepip")
    cands = sorted(p for p in lib.rglob("*.py") if not any(s in p.parts for s in skip) and 150 <= len(p.read_text(errors="ignore").splitlines()) <= 700)
    for i, p in enumerate(random.Random(1).sample(cands, 30)):
        shutil.copy(p, std / f"{i:02d}_{p.name}")
    pos = {f for f, n in gt.items() if n > 0}
    out = {"positives": len(pos), "benign_examples": len(gt) - len(pos), "in_scope_for_checksnap": len(set(IN_SCOPE) & pos)}
    tools = {}

    def run_bandit(d):
        r = sh([BV / "bandit", "-r", d, "-f", "json", "-q"])
        js = json.loads(r["out"] or "{}")
        return r["s"], [{"file": name(x["filename"]), "line": x["line_number"], "rule": x["test_id"]} for x in js.get("results", [])]

    def run_semgrep(d):
        r = sh([BV / "semgrep", "--config", "p/python", "--metrics=off", "--no-git-ignore", "--json", "--quiet", d], timeout=900)
        js = json.loads(r["out"] or "{}")
        return r["s"], [{"file": name(x["path"]), "line": x["start"]["line"], "rule": x["check_id"].split(".")[-1]} for x in js.get("results", [])]

    def run_cs(d, extra=()):
        s, fl, _ = cs(["--check-security", d, *extra])
        return s, [{"file": name(x["file"]), "line": x["line"], "rule": x["rule"]} for x in fl]

    def run_cs_ad(d):
        return run_cs(d, ["--with-adapters"])

    for tname, fn in (("bandit", run_bandit), ("semgrep p/python", run_semgrep), ("checksnap --check-security", run_cs),
                      ("checksnap+adapters --check-security --with-adapters", run_cs_ad)):
        s1, f1 = fn(str(ex)); s2, f2 = fn(str(std))
        byfile = {}
        for x in f1: byfile.setdefault(x["file"], set()).add(x["rule"])
        hit = {f for f in pos if f in byfile}
        t = {"examples_detected": len(hit), "examples_recall": round(len(hit) / len(pos), 3),
             "benign_examples_with_findings": sorted(f for f in gt if f not in pos and f in byfile), "seconds_examples": s1, "seconds_stdlib": s2}
        inscope = set(IN_SCOPE) & pos
        t["in_scope_detected"] = f"{len({f for f in inscope if f in byfile})}/{len(inscope)}"
        if tname == "bandit":
            t["in_scope_right_class"] = f"{sum(1 for f in inscope if byfile.get(f, set()) & BANDIT_CLASS[IN_SCOPE[f]])}/{len(inscope)}"
        elif tname.startswith("checksnap"):
            t["in_scope_right_class"] = f"{sum(1 for f in inscope if IN_SCOPE[f] in byfile.get(f, set()))}/{len(inscope)}"
        t["missed_in_scope"] = sorted(f for f in inscope if f not in byfile)
        sf = {}
        for x in f2: sf.setdefault(x["file"], []).append(x)
        t["stdlib_files_with_findings"] = f"{len(sf)}/30"; t["stdlib_findings_total"] = len(f2); t["stdlib_findings_per_file"] = round(len(f2) / 30, 2)
        t["stdlib_by_rule"] = {}
        for x in f2: t["stdlib_by_rule"][x["rule"]] = t["stdlib_by_rule"].get(x["rule"], 0) + 1
        (RAW / f"t1_stdlib_{tname.split()[0]}.json").write_text(json.dumps(f2, indent=1))
        tools[tname] = t
    out["tools"] = tools
    return out


# ---------------------------------------------------------------- task 2
def task2():
    sys.path.insert(0, str(HERE)); import gen_secrets
    truth = gen_secrets.main(DATA)
    pl, dc, dsd = DATA / "secrets/planted", DATA / "secrets/decoys", DATA / "secrets_ds"
    res = {}

    def score(findings, label):
        by = {}
        for f in findings: by.setdefault(f["file"], set()).add(f["line"])
        det = {n for n in truth if n in by}
        line = {n for n in truth if truth[n]["line"] in by.get(n, set()) or None in by.get(n, set()) and False}
        kinds = {}
        for n in truth:
            k = truth[n]["kind"]; kinds.setdefault(k, [0, 0]); kinds[k][1] += 1; kinds[k][0] += n in det
        fm = {}
        for n in truth:
            e = n.rsplit(".", 1)[1]; fm.setdefault(e, [0, 0]); fm[e][1] += 1; fm[e][0] += n in det
        return {"per_format": {k: f"{a}/{b}" for k, (a, b) in sorted(fm.items())}, "planted_files_detected": f"{len(det)}/60", "recall": round(len(det) / 60, 3), "line_exact": f"{len(line)}/60",
                "per_kind": {k: f"{a}/{b}" for k, (a, b) in kinds.items()}}

    def ds_run(d):
        r = sh([BV / "detect-secrets", "scan", "--all-files", d])
        js = json.loads(r["out"])["results"]
        return r["s"], [{"file": name(f), "line": x["line_number"], "rule": x["type"]} for f, xs in js.items() for x in xs]

    def ds_noent(d):
        r = sh([BV / "detect-secrets", "scan", "--all-files", "--disable-plugin", "Base64HighEntropyString", "--disable-plugin", "HexHighEntropyString", d])
        js = json.loads(r["out"])["results"]
        return r["s"], [{"file": name(f), "line": x["line_number"], "rule": x["type"]} for f, xs in js.items() for x in xs]

    for label, fn in (("detect-secrets", ds_run), ("detect-secrets (entropy plugins off)", ds_noent),
                      ("checksnap --check-security", lambda d: _csn(["--check-security", d])),
                      ("checksnap --check-config", lambda d: _csn(["--check-config", d]))):
        s1, fp = fn(str(pl)); s2, fd = fn(str(dc))
        r = score(fp, label)
        r.update({"decoy_files_with_findings": f"{len({x['file'] for x in fd})}/60", "decoy_findings": len(fd), "seconds": round(s1 + s2, 2),
                  "decoy_rules": sorted({x['rule'] for x in fd})})
        res[label] = r
    # union of checksnap checks (what --check-all runs)
    sp = _csn(["--check-security", str(pl)])[1] + _csn(["--check-config", str(pl)])[1]
    sd = _csn(["--check-security", str(dc)])[1] + _csn(["--check-config", str(dc)])[1]
    r = score(sp, "u"); r.update({"decoy_files_with_findings": f"{len({x['file'] for x in sd})}/60", "decoy_findings": len(sd)})
    res["checksnap security+config (union)"] = r
    # dataset PII rule on jsonl records (15 planted lines, 15 decoy lines)
    ds = {}
    s, fp = _csn(["--check-dataset", str(dsd / "planted.jsonl"), "--text-field", "text"])
    _, fd = _csn(["--check-dataset", str(dsd / "decoys.jsonl"), "--text-field", "text"])
    ds["checksnap --check-dataset"] = {"rules_on_planted": sorted({x["rule"] for x in fp}), "pii_findings_planted": len([x for x in fp if x["rule"].startswith("DS-PII")]), "pii_lines_planted": sorted({x["line"] for x in fp if x["rule"].startswith("DS-PII")}),
                                       "pii_findings_decoys": len([x for x in fd if x["rule"].startswith("DS-PII")]), "all_rules_decoys": sorted({x["rule"] for x in fd})}
    for lab, d in (("planted", dsd / "planted.jsonl"), ("decoys", dsd / "decoys.jsonl")):
        r = sh([BV / "detect-secrets", "scan", "--all-files", d]); js = json.loads(r["out"])["results"]
        ds.setdefault("detect-secrets", {})[lab + "_lines_flagged"] = sorted({x["line_number"] for xs in js.values() for x in xs})
    res["jsonl_records"] = ds
    return res


def _csn(args):
    s, fl, _ = cs(args)
    return s, [{"file": name(x["file"]), "line": x["line"], "rule": x["rule"]} for x in fl]


# ---------------------------------------------------------------- task 3
def _lint_all(d):
    """-> {tool: (seconds, [(file, line, code)])} for one directory."""
    out = {}
    r = sh([BV / "ruff", "check", "--select", "PERF,SIM,C4,B", "--output-format", "json", "--no-cache", "--isolated", "--no-respect-gitignore", d])
    out["ruff PERF,SIM,C4,B"] = (r["s"], [(name(x["filename"]), x["location"]["row"], x["code"]) for x in json.loads(r["out"] or "[]")])
    for lab, extra in (("pylint (default)", []), ("pylint (default, minus C docstring/naming)", ["--disable=C0114,C0115,C0116,C0103,C0104"])):
        r = sh([BV / "pylint", "--output-format=json", "--recursive=y", *extra, d])
        try: js = json.loads(r["out"] or "[]")
        except Exception: js = []
        out[lab] = (r["s"], [(name(x["path"]), x["line"], x["message-id"]) for x in js])
    r = sh([BV / "flake8", "--format=%(path)s|%(row)d|%(code)s", d])
    out["flake8 (default)"] = (r["s"], [(name(a), int(b), c) for a, b, c in (l.split("|") for l in r["out"].splitlines() if l.count("|") == 2)])
    s, fl, _ = cs(["--check-optimization", d, "--static-only"])
    out["checksnap --check-optimization --static-only"] = (s, [(name(x["file"]), x["line"], x["rule"]) for x in fl])
    s, fl, _ = cs(["--check-optimization", d, "--static-only", "--with-adapters"])
    out["checksnap+adapters --check-optimization --static-only --with-adapters"] = (s, [(name(x["file"]), x["line"], x["rule"]) for x in fl])
    return out


def task3():
    sys.path.insert(0, str(HERE)); import gen_perf
    gen_perf.main(DATA)
    truth = json.load(open(DATA / "perf/truth.json"))
    bug = _lint_all(str(DATA / "perf/bug")); clean = _lint_all(str(DATA / "perf/clean"))
    res = {}
    for tool in bug:
        s1, fb = bug[tool]; s2, fc = clean[tool]
        hit = {k: any(f == k and l in v["lines"] for f, l, _ in fb) for k, v in truth.items()}
        file_hit = {k: any(f == k for f, _, _ in fb) for k in truth}
        ins = [k for k, v in truth.items() if v["in_scope"]]; out_ = [k for k, v in truth.items() if not v["in_scope"]]
        labeled = {(k, l) for k, v in truth.items() for l in v["lines"]}
        other = [x for x in fb if (x[0], x[1]) not in labeled]
        res[tool] = {"line_recall_all": f"{sum(hit.values())}/40", "line_recall_checksnap_families": f"{sum(hit[k] for k in ins)}/{len(ins)}",
                     "line_recall_outside_families": f"{sum(hit[k] for k in out_)}/{len(out_)}", "any_finding_on_bug_file": f"{sum(file_hit.values())}/40",
                     "clean_files_with_findings": f"{len({f for f, _, _ in fc})}/40", "clean_findings_total": len(fc),
                     "clean_codes": _count(c for _, _, c in fc), "other_findings_in_bug_files": len(other), "seconds": round(s1 + s2, 2),
                     "missed_in_families": [k for k in ins if not hit[k]]}
        tp = sum(hit.values()); fp = len(fc) + len(other)
        P = tp / max(1, tp + fp); Rr = tp / 40
        res[tool]["precision_line"] = round(P, 3); res[tool]["f1_line"] = round(2 * P * Rr / max(1e-9, P + Rr), 3)
    return res


def _count(it):
    d = {}
    for x in it: d[x] = d.get(x, 0) + 1
    return dict(sorted(d.items(), key=lambda kv: -kv[1])[:8])


# ---------------------------------------------------------------- task 4
def task4():
    t4 = DATA / "t4"; shutil.rmtree(t4, ignore_errors=True)
    rng = random.Random(4)
    wf_src = sorted(p for r in ("requests", "flask", "fastapi", "bandit") for p in (DATA / r / ".github/workflows").glob("*.y*ml"))
    ci = t4 / "ci/.github/workflows"; ci.mkdir(parents=True)
    for p in rng.sample(wf_src, 20): shutil.copy(p, ci / f"{p.parents[2].name}__{p.name}")
    dk_src = sorted(set(p for r in ("awesome-compose", "uvicorn-gunicorn-docker", "bandit") for p in (DATA / r).rglob("*") if p.is_file() and (p.name == "Dockerfile" or p.name.endswith(".dockerfile") or p.name.startswith("Dockerfile."))))
    dk = t4 / "docker"; dk.mkdir()
    for i, p in enumerate(rng.sample(dk_src, 20)):       # one dir per Dockerfile; keep a sibling .dockerignore if the repo had one
        (dk / f"{i:02d}_{p.parent.name}").mkdir(); shutil.copy(p, dk / f"{i:02d}_{p.parent.name}" / "Dockerfile")
        if (p.parent / ".dockerignore").exists(): shutil.copy(p.parent / ".dockerignore", dk / f"{i:02d}_{p.parent.name}" / ".dockerignore")
    ya_src = sorted(p for r in ("requests", "flask", "fastapi", "bandit") for p in (DATA / r).glob("*.y*ml")) + sorted((DATA / "fastapi/docs/en").glob("*.yml"))
    ya = t4 / "yaml"; ya.mkdir()
    for p in (list(ci.glob("*"))[:12] + rng.sample(ya_src, min(8, len(ya_src)))): shutil.copy(p, ya / p.name if p.parent == ci else ya / f"{p.parent.name}__{p.name}")
    sq_src = [p for r in ("sakila", "test_db") for p in (DATA / r).rglob("*.sql") if p.stat().st_size < 60_000]
    sq = t4 / "sql"; sq.mkdir()
    chosen = rng.sample(sorted(sq_src), 15)
    for i, p in enumerate(chosen): shutil.copy(p, sq / f"{i:02d}_{p.parent.name}_{p.name}")
    dialect = {}
    for f in sq.glob("*.sql"):
        n = f.name.lower()
        dialect[f.name] = "postgres" if ("postgres" in n or "yuga" in n) else "sqlite" if "sqlite" in n else "tsql" if "sql-server" in n else "db2" if "db2" in n else "mysql"
    res = {"sample_sizes": {"workflows": 20, "dockerfiles": 20, "yaml": len(list(ya.glob("*"))), "sql": 15}}
    allf = {}

    # --- docker
    r = sh([BIN / "hadolint", "-f", "json", "--no-fail", *sorted(dk.glob("*/Dockerfile"))])
    hl = [{"file": name2(x["file"]), "line": x["line"], "rule": x["code"], "msg": x["message"]} for x in json.loads(r["out"] or "[]")]
    s, fl, _ = cs(["--check-docker", str(dk)])
    cd = [{"file": name2(x["file"]), "line": x["line"], "rule": x["rule"], "msg": x["title"]} for x in fl]
    bad = {x["file"] for x in hl if x["rule"] == "DL1000"}
    hl = [x for x in hl if x["rule"] != "DL1000"]
    cd_ok = [x for x in cd if x["file"] not in bad]
    allf["hadolint"], allf["checksnap-docker"] = hl, cd
    res["docker"] = {"hadolint": {"findings_excl_parse_errors": len(hl), "files_hadolint_failed_to_parse(DL1000 heredoc)": len(bad), "seconds": r["s"]},
                     "checksnap --check-docker": {"findings_all_20_files": len(cd), "findings_on_the_files_hadolint_parsed": len(cd_ok), "seconds": s},
                     **_overlap(hl, cd_ok, DOCK_MAP)}
    # --- CI (actionlint vs checksnap --check-ci)
    r = sh([BIN / "actionlint", "-format", "{{json .}}", *sorted(ci.glob("*"))])
    al = [{"file": name(x["filepath"]), "line": x["line"], "rule": x["kind"], "msg": x["message"]} for x in json.loads(r["out"] or "[]")]
    s, fl, _ = cs(["--check-ci", str(t4 / "ci")])
    cc = [{"file": name(x["file"]), "line": x["line"], "rule": x["rule"], "msg": x["title"]} for x in fl]
    allf["actionlint"], allf["checksnap-ci"] = al, cc
    res["ci"] = {"actionlint": {"findings": len(al), "seconds": r["s"], "by_kind": _count(x["rule"] for x in al)},
                 "checksnap --check-ci": {"findings": len(cc), "seconds": s, "by_rule": _count(x["rule"] for x in cc)}, **_overlap(al, cc, {})}
    # --- YAML (yamllint default vs checksnap --check-config)
    r = sh([BV / "yamllint", "-f", "parsable", ya])
    yl = [{"file": name(l.split(":")[0]), "line": int(l.split(":")[1]), "rule": (re.findall(r"\(([a-z-]+)\)\s*$", l) or ["?"])[0], "msg": l.split("] ", 1)[-1]}
          for l in r["out"].splitlines() if l.count(":") >= 3]
    s, fl, _ = cs(["--check-config", str(ya)])
    cy = [{"file": name(x["file"]), "line": x["line"], "rule": x["rule"], "msg": x["title"]} for x in fl]
    allf["yamllint"], allf["checksnap-config"] = yl, cy
    res["yaml"] = {"yamllint": {"findings": len(yl), "seconds": r["s"], "by_rule": _count(x["rule"] for x in yl)},
                   "checksnap --check-config": {"findings": len(cy), "seconds": s, "by_rule": _count(x["rule"] for x in cy)}, **_overlap(yl, cy, {})}
    # --- SQL
    sf, secs = [], 0.0
    for dia in sorted(set(dialect.values())):
        files = [sq / f for f, d in dialect.items() if d == dia]
        r = sh([BV / "sqlfluff", "lint", "--dialect", dia, "--format", "json", *files], timeout=900)
        secs += r["s"]
        try:
            for fo in json.loads(r["out"] or "[]"):
                for v in fo["violations"]:
                    sf.append({"file": name(fo["filepath"]), "line": v["start_line_no"], "rule": v["code"], "msg": v["description"]})
        except Exception:
            sf.append({"file": "?", "line": 0, "rule": "ERR", "msg": r["out"][:200] + r["err"][:200]})
    s, fl, _ = cs(["--check-sql", str(sq)])
    cq = [{"file": name(x["file"]), "line": x["line"], "rule": x["rule"], "msg": x["title"]} for x in fl]
    allf["sqlfluff"], allf["checksnap-sql"] = sf, cq
    res["sql"] = {"sqlfluff": {"findings": len(sf), "seconds": round(secs, 2), "by_rule": _count(x["rule"] for x in sf), "parse_errors(PRS/TMP)": sum(x["rule"] in ("PRS", "TMP") for x in sf)},
                  "checksnap --check-sql": {"findings": len(cq), "seconds": s, "by_rule": _count(x["rule"] for x in cq)}, **_overlap(sf, cq, {})}
    (RAW / "t4_findings.json").write_text(json.dumps(allf, indent=1))
    # 15 random findings per tool for manual true/false judging (seed 15), with the source line
    sample = {}
    srcdir = {"hadolint": dk, "checksnap-docker": dk, "actionlint": ci, "checksnap-ci": ci, "yamllint": ya, "checksnap-config": ya, "sqlfluff": sq, "checksnap-sql": sq}
    for tool, fl in allf.items():
        pick = random.Random(15).sample(fl, min(15, len(fl)))
        for x in pick:
            try: x["src"] = (srcdir[tool] / x["file"]).read_text(errors="replace").splitlines()[x["line"] - 1].strip()[:160] if x["line"] else ""
            except Exception: x["src"] = ""
        sample[tool] = pick
    (RAW / "t4_sample15.json").write_text(json.dumps(sample, indent=1))
    jf = HERE / "judgments.json"
    if jf.exists():
        res["manual_judgement_15_each"] = json.loads(jf.read_text())
    return res


DOCK_MAP = {  # hadolint code -> checksnap rule that covers the same concern
    "DL3006": "DOC-001", "DL3007": "DOC-001", "DL3002": "DOC-002", "DL3020": "DOC-003", "DL3015": "DOC-004", "DL3009": "DOC-005",
    "DL3042": "DOC-007", "DL3003": None, "DL4006": None}


def _overlap(a, b, m):
    """File+line coincidence, and (for Dockerfiles) same-concern coincidence via m."""
    A = {(x["file"], x["line"]) for x in a}; B = {(x["file"], x["line"]) for x in b}
    r = {"same_file_line": len(A & B), "only_first_tool_locations": len(A - B), "only_checksnap_locations": len(B - A)}
    if m:
        pairs = {(x["file"], m[x["rule"]]) for x in a if m.get(x["rule"])}
        bs = {(x["file"], x["rule"]) for x in b}
        r["same_concern_file_pairs"] = {"hadolint_mapped": len(pairs), "also_checksnap": len(pairs & bs)}
        r["hadolint_codes"] = _count(x["rule"] for x in a)
        r["checksnap_rules"] = _count(x["rule"] for x in b)
    return r


# ---------------------------------------------------------------- task 5
BATCH_SIZE = 10


def _bank_args(d, top):
    return ["--check-bank", str(d), "--bank-top", str(top), "--yes", "--budget-tokens", "400000", "--cache-dir", str(HERE / ".snapcache"),
            "--format", "json", "--fail-on", "none"]


def _bank_run(d, top, tag):
    """Real-API run; the result is saved to raw/bank_<tag>.json and re-used on later invocations (re-running spends nothing)."""
    saved = RAW / f"bank_{tag}.json"
    if saved.exists():
        j = json.loads(saved.read_text()); return j["result"], j["seconds"]
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    key_sh = "set -a; . /home/aras/Projects/_scan_test/snap-contamination-scanner/.env >/dev/null 2>&1; set +a; "
    cmd = key_sh + f"exec nice -n 10 {CSPY} -m checksnap " + " ".join(map(str, _bank_args(d, top)))
    t = time.perf_counter()
    p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=900)
    doc = json.loads(p.stdout)
    secs = round(time.perf_counter() - t, 1)
    saved.write_text(json.dumps({"result": doc["results"][0], "seconds": secs}))
    return doc["results"][0], secs


def task5(spend=True):
    sys.path.insert(0, str(HERE)); import gen_bank
    gen_bank.main(DATA)
    truth = json.load(open(DATA / "bank/truth.json")); proj = DATA / "bank/proj"
    planted = {fn: v["item"] for fn, v in truth.items() if v["kind"] == "bug"}
    res = {"files": 60, "planted_items": 30}
    # A. one project, --bank-top 50 (as specified) then --bank-top 200 (all cached, 0 tokens) to see every flagged item
    r50, s50 = _bank_run(proj, 50, "proj_top50"); r200, s200 = _bank_run(proj, 200, "proj_top200")
    fl = r200["findings"]; rank = {f["rule_id"]: i + 1 for i, f in enumerate(fl)}
    top50_ids = {f["rule_id"] for f in r50["findings"]}
    items = set(planted.values())
    found = {i for i in items if i in rank}
    res["project_run"] = {"seconds_first_run": s50, "input_tokens_first_run": r50["usage"]["input_tokens"], "snap_calls": r50["usage"]["snap_calls"],
                          "items_asked": r50["stats"]["items_asked"], "flagged_ge_0.5": r200["stats"]["flagged"],
                          "planted_flagged_any_rank": f"{len(found)}/30", "planted_in_top5": sum(rank.get(i, 999) <= 5 for i in items),
                          "planted_in_top25": sum(rank.get(i, 999) <= 25 for i in items), "planted_in_top50": sum(rank.get(i, 999) <= 50 for i in items),
                          "off_target_flagged": r200["stats"]["flagged"] - len(found), "calibration": r200["stats"]["calibration"],
                          "planted_missed": sorted(items - found)}
    # file attribution: only the first MAX_LOCALIZE=10 findings get a file/line; the rest list the first <=5 files of the window
    byitem = {}
    for fn, it in planted.items(): byitem[it] = fn
    loc_ok = loc_n = 0; clean_fp_files = set(); win_ok = 0
    for f in fl:
        ev = f["evidence"]; localized = len(ev) == 1 and ev[0]["file"]
        if f["rule_id"] in byitem and localized:
            loc_n += 1; loc_ok += ev[0]["file"] == byitem[f["rule_id"]]
        if f["rule_id"] in byitem and len(ev) > 1:
            win_ok += byitem[f["rule_id"]] in {e["file"] for e in ev}
        if localized and ev[0]["file"] and truth[ev[0]["file"]]["kind"] == "clean": clean_fp_files.add(ev[0]["file"])
    res["project_run"].update({"localized_planted_findings": loc_n, "localized_to_correct_file": loc_ok,
                               "unlocalized_planted_whose_listed_files_contain_the_bug_file": win_ok,
                               "clean_files_blamed_by_localized_findings": len(clean_fp_files)})
    # B. six 10-file projects (5 buggy + 5 clean files of other items) -> per-file noise and recall in small projects
    files = sorted(truth); bugs = [f for f in files if truth[f]["kind"] == "bug"]; cleans = [f for f in files if truth[f]["kind"] == "clean"]
    rng = random.Random(5); rng.shuffle(bugs)
    batches = []
    for k in range(6):
        bb = bugs[k * 5:(k + 1) * 5]
        pool = [c for c in cleans if truth[c]["item"] not in {truth[b]["item"] for b in bb}]
        rng2 = random.Random(100 + k); cb = rng2.sample(pool, 5)
        batches.append((bb, cb))
    tot = {"tokens": 0, "seconds": 0.0, "planted": 0, "found": 0, "found_top5": 0, "off_target": 0, "flagged": 0, "clean_files": 0, "per_batch": []}
    for k, (bb, cb) in enumerate(batches):
        d = DATA / f"bank/b{k}"; shutil.rmtree(d, ignore_errors=True); d.mkdir()
        for f in bb + cb: shutil.copy(proj / f, d / f)
        r, s = _bank_run(d, 200, f"batch{k}")
        its = {truth[b]["item"] for b in bb}; ids = [f["rule_id"] for f in r["findings"]]
        fnd = its & set(ids)
        tot["tokens"] += r["usage"]["input_tokens"]; tot["seconds"] += s; tot["planted"] += 5; tot["found"] += len(fnd)
        tot["found_top5"] += sum(i in ids[:5] for i in its); tot["flagged"] += r["stats"]["flagged"]; tot["off_target"] += r["stats"]["flagged"] - len(fnd)
        tot["clean_files"] += 5
        tot["per_batch"].append({"flagged": r["stats"]["flagged"], "found": len(fnd), "off_target": r["stats"]["flagged"] - len(fnd),
                                 "tokens": r["usage"]["input_tokens"], "off_target_ids": sorted(set(ids) - its)})
    # grounding proxy: an off-target flag is "unsupported" if the item's own regex hint matches nothing in that batch's code
    sys.path.insert(0, str(ROOT)); from checksnap.checks.bank import engine
    its, _ = engine.load_items(None); hints = engine.compile_hints(its, [])
    sup = uns = nh = 0
    for k, b in enumerate(tot["per_batch"]):
        text = "\n".join(p.read_text() for p in (DATA / f"bank/b{k}").glob("*.py"))
        for it in b["off_target_ids"]:
            pats = hints.get(it) or []
            if not pats: nh += 1
            elif any(p.search(text) for p in pats): sup += 1
            else: uns += 1
    tot["off_target_hint_proxy"] = {"hint_matches_somewhere": sup, "hint_matches_nothing(likely_unsupported)": uns, "item_has_no_hint": nh}
    tot["off_target_per_file"] = round(tot["off_target"] / 60, 2); tot["off_target_per_10_file_project"] = round(tot["off_target"] / 6, 1); tot["seconds"] = round(tot["seconds"], 1)
    tot["recall"] = f"{tot['found']}/30"; tot["recall_top5_in_batch"] = f"{tot['found_top5']}/30"
    res["small_projects_10_files_each"] = tot
    res["total_input_tokens_all_bank_runs"] = r50["usage"]["input_tokens"] + tot["tokens"]
    # C. static comparators on the same 60 files
    res["comparators"] = _t5_static(proj, truth)
    return res


RELEVANT = {  # item -> substrings of rule codes that genuinely address the planted bug
    "BANK-SEC-011": ("S605", "B605", "S602", "B602"), "BANK-SEC-018": ("S311", "B311"), "BANK-RELIAB-001": ("S110", "B110", "BLE001", "W0718", "S112", "SIM105", "W0702"),
    "API-002": ("B006", "W0102"), "BANK-RELIAB-016": ("SIM115", "R1732"), "BANK-RELIAB-041": ("S603", "B603", "PLW1510", "W1510", "subprocess-run-check"),
    "PERF-GEN-003": ("S113", "W3101", "B113"), "BANK-SEC-023": ("S", "B") if False else ("NONE",), "BANK-SEC-013": ("B703", "S704", "B701"),
    "BANK-SEC-010": ("S",) if False else ("NONE",), "BANK-RELIAB-013": ("NONE",), "BANK-SEC-026": ("NONE",)}


def _t5_static(proj, truth):
    out = {}
    runs = {}
    r = sh([BV / "ruff", "check", "--select", "B,S,PERF,SIM,BLE,ASYNC,RUF,E,F", "--output-format", "json", "--no-cache", "--isolated", "--no-respect-gitignore", proj])
    runs["ruff B,S,PERF,SIM,BLE,ASYNC,RUF,E,F"] = (r["s"], [(name(x["filename"]), x["code"]) for x in json.loads(r["out"] or "[]")])
    r = sh([BV / "pylint", "--output-format=json", "--recursive=y", "--disable=C", proj])
    runs["pylint (default minus C)"] = (r["s"], [(name(x["path"]), x["message-id"] + ":" + x["symbol"]) for x in json.loads(r["out"] or "[]")])
    r = sh([BV / "bandit", "-r", proj, "-f", "json", "-q"])
    runs["bandit"] = (r["s"], [(name(x["filename"]), x["test_id"]) for x in json.loads(r["out"] or "{}").get("results", [])])
    s1, a, _ = cs(["--check-security", str(proj)]); s2, b, _ = cs(["--check-optimization", str(proj), "--static-only"]); s3, c, _ = cs(["--check-reproducibility", str(proj)])
    runs["checksnap static (security+optimization)"] = (round(s1 + s2, 2), [(name(x["file"]), x["rule"]) for x in a + b])
    for tool, (secs, fl) in runs.items():
        by = {}
        for f, c_ in fl: by.setdefault(f, []).append(c_)
        bug = [f for f in truth if truth[f]["kind"] == "bug"]; cl = [f for f in truth if truth[f]["kind"] == "clean"]
        rel = sum(any(any(s in code for s in RELEVANT.get(truth[f]["item"], ("NONE",))) for code in by.get(f, [])) for f in bug)
        out[tool] = {"buggy_files_with_any_finding": f"{sum(f in by for f in bug)}/30", "buggy_files_with_relevant_finding": f"{rel}/30",
                     "clean_files_with_any_finding": f"{sum(f in by for f in cl)}/30", "clean_findings": sum(len(by.get(f, [])) for f in cl),
                     "seconds": round(secs, 2), "clean_codes": _count(c_ for f in cl for c_ in by.get(f, []))}
    out["_note"] = ("'relevant' = hand-listed rule codes that actually describe the planted bug (RELEVANT in run_all.py); items with no listed code "
                    "cannot count. 'any finding' is an upper bound that rewards noise.")
    return out


# ---------------------------------------------------------------- task 6
def task6():
    snap = DATA / "t6/checksnap"; shutil.rmtree(DATA / "t6", ignore_errors=True)
    shutil.copytree(ROOT, snap, ignore=shutil.ignore_patterns(".venv", ".bench-venv", ".git", "data", "raw", "bin", "dl", "__pycache__", ".snapcache", ".checksnap-cache", ".pytest_cache", "*.egg-info"))
    repos = {"checksnap (self, copy)": snap, "requests": DATA / "requests"}
    res = {}
    for label, d in repos.items():
        pyf = sum(1 for _ in Path(d).rglob("*.py")); loc = sum(len(p.read_text(errors="ignore").splitlines()) for p in Path(d).rglob("*.py"))
        row = {"py_files": pyf, "py_loc": loc, "tools": {}}
        raw = {}
        cmds = {
            "bandit -r": [BV / "bandit", "-r", d, "-q", "-f", "json"],
            "semgrep p/python": [BV / "semgrep", "--config", "p/python", "--metrics=off", "--no-git-ignore", "--json", "--quiet", d],
            "detect-secrets": [BV / "detect-secrets", "scan", "--all-files", d],
            "ruff PERF,SIM,C4,B": [BV / "ruff", "check", "--select", "PERF,SIM,C4,B", "--no-cache", "--isolated", "--no-respect-gitignore", "--output-format", "json", d],
            "pylint (default)": [BV / "pylint", "--recursive=y", "--output-format=json", d],
            "flake8": [BV / "flake8", d],
            "yamllint": [BV / "yamllint", "-f", "parsable", d],
            "sqlfluff lint (ansi)": [BV / "sqlfluff", "lint", "--dialect", "ansi", "--format", "json", d],
        }
        for k, c in cmds.items():
            r = sh(c, timeout=1500); row["tools"][k] = {"seconds": r["s"], "raw_chars": len(r["out"])}; raw[k] = r["out"]
        s, fl, doc = cs(["--check-all", str(d)]); r = sh([CSPY, "-m", "checksnap", "--check-all", str(d), "--no-snap", "--format", "json", "--fail-on", "none"], env={"PYTHONPATH": str(ROOT), "SUBQ_API_KEY": ""})
        row["tools"]["checksnap --check-all --no-snap"] = {"seconds": r["s"], "raw_chars": len(r["out"]), "findings": len(fl)}
        row["tools"]["checksnap --check-all --no-snap"]["seconds_by_check"] = {x["check"]: x["duration_s"] for x in doc.get("results", [])}
        tot_raw = sum(v["raw_chars"] for k, v in row["tools"].items() if not k.startswith("checksnap"))
        # plugin digest (mcp_server.checksnap_scan, auto checks, defaults: min_severity=medium, top=15, CAP 3000 chars)
        code = ("import sys,json,time; sys.path.insert(0,%r); import mcp_server as m; t=time.perf_counter(); "
                "o=m.t_scan({'path':%r}); sys.__stderr__.write(json.dumps({'chars':len(o),'s':round(time.perf_counter()-t,2),'text':o}))") % (str(ROOT), str(d))
        r = sh([CSPY, "-c", code], env={"SUBQ_API_KEY": ""})
        try: dg = json.loads(r["err"].strip().splitlines()[-1])
        except Exception: dg = {"chars": -1, "s": r["s"], "text": r["err"][-300:]}
        row["plugin_digest"] = {"chars": dg["chars"], "approx_tokens": dg["chars"] // 4, "seconds": dg["s"]}
        row["sum_raw_chars_other_tools"] = tot_raw
        row["digest_vs_raw_other_tools"] = round(dg["chars"] / max(1, tot_raw), 5)
        row["checksnap_full_json_chars"] = len(r["out"]) if False else row["tools"]["checksnap --check-all --no-snap"]["raw_chars"]
        (RAW / f"t6_digest_{label.split()[0]}.txt").write_text(dg["text"])
        res[label] = row
    return res


# ---------------------------------------------------------------- after-improvements: t5a (bank, real API), t7 (--snap-verify, real API)
KEY_SH = "set -a; . /home/aras/Projects/_scan_test/snap-contamination-scanner/.env >/dev/null 2>&1; set +a; "


def _real(args, cache, budget="300000", dry=False):
    """checksnap with the key sourced inside the shell (never printed). -> (doc | stdout text, seconds)."""
    fmt = ["--dry-run"] if dry else ["--yes", "--budget-tokens", budget, "--format", "json", "--fail-on", "none"]
    cmd = KEY_SH + f"exec nice -n 10 {CSPY} -m checksnap " + " ".join(map(str, [*args, *fmt, "--cache-dir", cache]))
    t = time.perf_counter()
    p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT)), timeout=900)
    return (p.stdout + p.stderr if dry else json.loads(p.stdout)), round(time.perf_counter() - t, 1)


def task5a():
    """Same 60 files as task5 (data NOT regenerated), after-improvements checksnap, fresh cache so tokens are really spent (<=300k cap)."""
    truth = json.load(open(DATA / "bank/truth.json")); proj = DATA / "bank/proj"
    planted = {fn: v["item"] for fn, v in truth.items() if v["kind"] == "bug"}; byitem = {v: k for k, v in planted.items()}
    cache = str(HERE / ".snapcache_costfix"); saved = RAW / "bank_costfix_proj.json"      # fresh cache: tokens really spent
    args = ["--check-bank", str(proj), "--bank-top", "200"]
    if saved.exists():
        j = json.loads(saved.read_text()); r, secs, est_txt = j["result"], j["seconds"], j["dry_run"]
    else:
        est_txt, _ = _real(args, cache, dry=True)
        doc, secs = _real(args, cache, budget="120000"); r = doc["results"][0]
        saved.write_text(json.dumps({"result": r, "seconds": secs, "dry_run": est_txt}))
    m = re.search(r"^bank\s+\S+ KB\s+(\d+)\s+([\d,]+)", est_txt, re.M)
    est_tokens = int(m.group(2).replace(",", "")) if m else None
    fl = r["findings"]; rank = {f["rule_id"]: i + 1 for i, f in enumerate(fl)}; items = set(planted.values()); st = r["stats"]
    found = {i for i in items if i in rank}
    out = {"seconds": secs, "input_tokens": r["usage"]["input_tokens"], "snap_calls": r["usage"]["snap_calls"], "dry_run_estimate_tokens": est_tokens,
           "dry_run_includes_baseline": "baseline" in est_txt, "items_asked": st["items_asked"], "flagged_ge_0.5": st["flagged"], "suppressed": st.get("suppressed", 0),
           "findings_shown": len(fl), "clean_code_fire_rate": st.get("clean_code_fire_rate"), "calibration": st["calibration"],
           "planted_findings_surviving": f"{len(found)}/30", "planted_missed_or_suppressed": sorted(items - found)}
    for k in (5, 10, 25, 50):
        out[f"precision@{k}"] = f"{sum(f['rule_id'] in items for f in fl[:k])}/{min(k, len(fl))}"
    ex = lambda f: (f["evidence"][0].get("extra") or {}) if f["evidence"] else {}  # noqa: E731
    files_of = lambda f: [e["file"] for e in f["evidence"] if e["file"]]  # noqa: E731
    loc = [f for f in fl if len(f["evidence"]) == 1 and files_of(f) and ex(f).get("localized")]          # Snap-localized, one file
    hint = [f for f in fl if files_of(f) and f not in loc]                                                 # regex-hint attribution, 1-3 files
    none = [f for f in fl if not files_of(f)]                                                              # "somewhere in these N files"
    pl = [f for f in fl if f["rule_id"] in items]
    ok = [f for f in pl if f in loc and files_of(f)[0] == byitem[f["rule_id"]]]
    hint_ok = [f for f in pl if f in hint and byitem[f["rule_id"]] in files_of(f)]
    cl_blame = {x for f in loc + hint for x in files_of(f) if truth[x]["kind"] == "clean"}
    out.update({"findings_localized_to_one_file": len(loc), "planted_localized": sum(f in loc for f in pl), "planted_localized_correct_file": len(ok),
                "findings_hint_attributed": len(hint), "planted_hint_attributed": sum(f in hint for f in pl), "planted_hint_attributed_includes_bug_file": len(hint_ok),
                "findings_unattributed_somewhere_in_N_files": len(none), "planted_unattributed": sum(f in none for f in pl),
                "clean_files_blamed": len(cl_blame), "localized_findings_on_clean_files": sum(files_of(f)[0] in cl_blame for f in loc),
                "off_target_shown": len(fl) - len(found), "localize_calls_and_tokens_included_in_usage": True})
    out["notes"] = r["notes"]
    return out


def task7():
    """--snap-verify on the security check (real API): stdlib 30 clean-ish files + vulnerable bandit examples."""
    sv, vd = DATA / "t1/verify", DATA / "t1/verify_vuln"
    shutil.rmtree(vd, ignore_errors=True); vd.mkdir()
    pick = ["eval.py", "pickle_deserialize.py", "yaml_load.py", "flask_debug.py", "subprocess_shell.py", "os_system.py", "crypto-md5.py",
            "requests-ssl-verify-disabled.py", "tarfile_extractall.py", "sql_statements.py", "mktemp.py", "os-chmod.py"]
    for f in pick: shutil.copy(DATA / "t1/cases" / f, vd / f)
    shutil.rmtree(sv, ignore_errors=True); sv.mkdir()
    for p in (DATA / "t1/stdlib").glob("*.py"): shutil.copy(p, sv / p.name)
    out = {}; cache = str(HERE / ".snapcache_verify")
    for label, d in (("stdlib_30", sv), ("vulnerable_12", vd)):
        saved = RAW / f"verify_{label}.json"
        _, base, _ = cs(["--check-security", str(d), "--with-adapters"])
        if saved.exists(): j = json.loads(saved.read_text())
        else:
            doc, secs = _real(["--check-security", str(d), "--with-adapters", "--snap-verify"], cache, budget="60000")
            j = {"result": doc["results"][0], "seconds": secs}; saved.write_text(json.dumps(j))
        r = j["result"]; v = r["stats"].get("verify", {})
        lowered = [{"rule": f["rule_id"], "file": name(f["evidence"][0]["file"]), "line": f["evidence"][0]["line_start"], "sev": f["severity"], "score": f.get("score")}
                   for f in r["findings"] if "snap judged unlikely" in (f.get("detail") or "")]
        out[label] = {"findings_total": len(r["findings"]), "verify_stats": {k: v.get(k) for k in ("candidates", "checked", "lowered")}, "sev_before": v.get("before"), "sev_after": v.get("after"),
                      "lowered": lowered, "input_tokens": r["usage"]["input_tokens"], "snap_calls": r["usage"]["snap_calls"], "seconds": j["seconds"], "notes": r["notes"],
                      "all_findings": [{"rule": f["rule_id"], "file": name(f["evidence"][0]["file"]), "line": f["evidence"][0]["line_start"], "sev": f["severity"], "score": f.get("score")} for f in r["findings"]]}
    return out


TASKS = {"t1": task1, "t2": task2, "t3": task3, "t4": task4, "t5": task5, "t6": task6}
AFTER = {"t5a": task5a, "t7": task7}      # real-API tasks of the after-improvements run; not in the default list, ask for them by name
TASKS.update(AFTER)
if __name__ == "__main__":
    which = sys.argv[1:] or [t for t in TASKS if t not in AFTER]
    if "versions" in which or not sys.argv[1:]:
        save("versions", versions())
    for t in which:
        if t in TASKS:
            t0 = time.perf_counter(); r = TASKS[t](); r["_wall_s"] = round(time.perf_counter() - t0, 1); save(t, r)
            print(t, "done", r["_wall_s"], "s")
