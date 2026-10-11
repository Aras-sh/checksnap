"""Every SQL rule: one positive (right id, right line) and one negative source, plus tokenizer and end-to-end checks."""
from __future__ import annotations

import argparse
from pathlib import Path

from checksnap.checks.sqlcheck import RULES, SqlCheck
from checksnap.checks.sqlcheck.scan import analyze, analyze_files, tokenize
from checksnap.core import Context

FX = Path(__file__).parent / "fixtures" / "sqlcheck"
PG = "-- pg\nCREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
# rule id -> (positive source, expected line, negative source)
CASES = {
    "SQL-001": ("SELECT * FROM t;\n", 1, "SELECT a FROM t;\nSELECT count(*) FROM t;\nSELECT 1 WHERE EXISTS (SELECT * FROM u);\n-- SELECT * FROM t\nSELECT 'SELECT * x';\n"),
    "SQL-002": ("SELECT 1;\nDELETE FROM t;\n", 2, "DELETE FROM t WHERE id = 1;\nUPDATE t SET a = 1 WHERE id IN (SELECT 1);\nINSERT INTO t VALUES (1) ON CONFLICT DO UPDATE SET a = 2;\n"),
    "SQL-003": ("DROP TABLE t;\n", 1, "DROP TABLE IF EXISTS t;\n-- +goose Down\nDROP TABLE t;\n"),
    "SQL-004": ("CREATE TABLE t (a int);\n", 1, "CREATE TABLE t (a int PRIMARY KEY);\nCREATE TABLE u (a int, b int, PRIMARY KEY (a, b));\nCREATE TEMP TABLE v (a int);\n"),
    "SQL-005": ("CREATE TABLE t (id int PRIMARY KEY, user_id int);\n", 1,
                "CREATE TABLE t (id int PRIMARY KEY, user_id int REFERENCES u(id));\nCREATE TABLE s (id int PRIMARY KEY, org_id int);\nCREATE INDEX i ON s (org_id);\n"),
    "SQL-006": ("SELECT a FROM t WHERE n LIKE '%x';\n", 1, "SELECT a FROM t WHERE n LIKE 'x%';\nSELECT a FROM t WHERE n = '%x';\n"),
    "SQL-007": ("SELECT a FROM t WHERE a NOT IN (SELECT b FROM u);\n", 1, "SELECT a FROM t WHERE a NOT IN (1, 2);\nSELECT a FROM t WHERE NOT EXISTS (SELECT 1);\n"),
    "SQL-008": ("SELECT a FROM t, u WHERE t.id = u.id;\n", 1,
                "SELECT a FROM t JOIN u ON t.id = u.id;\nSELECT extract(year FROM d), x FROM t;\nSELECT a FROM t, LATERAL f(t.id);\nREVOKE ALL ON t FROM a, b;\n"),
    "SQL-009": ("SELECT a FROM t ORDER BY RANDOM() LIMIT 1;\n", 1, "SELECT a FROM t ORDER BY a LIMIT 1;\nSELECT random() FROM t;\n"),
    "SQL-010": ("CREATE INDEX i ON t (email);\nSELECT a FROM t WHERE LOWER(email) = 'x';\n", 2,
                "CREATE INDEX i ON t (email);\nSELECT a FROM t WHERE email = 'x';\nSELECT a FROM t WHERE LOWER(name) = 'x';\n"),
    "SQL-011": (PG + "CREATE INDEX i ON t (a);\n", 3, PG + "CREATE INDEX CONCURRENTLY i ON t (a);\nCREATE TABLE n (a int PRIMARY KEY);\nCREATE INDEX j ON n (a);\n"),
    "SQL-012": ("ALTER TABLE t ADD COLUMN c int NOT NULL;\n", 1, "ALTER TABLE t ADD COLUMN c int NOT NULL DEFAULT 0;\nALTER TABLE t ADD COLUMN d int;\n"),
    "SQL-013": ("CREATE TABLE t (id int PRIMARY KEY, unit_price double precision);\n", 1, "CREATE TABLE t (id int PRIMARY KEY, price numeric(10,2), tax_rate float, score float);\n"),
    "SQL-014": ("CREATE TABLE t (id int PRIMARY KEY, a varchar(255), b varchar(255), c varchar(255));\n", 1,
                "CREATE TABLE t (id int PRIMARY KEY, a varchar(255), b varchar(40), c varchar(80), d varchar(255));\n"),
    "SQL-015": ("GRANT ALL PRIVILEGES ON t TO app;\n", 1, "GRANT SELECT, INSERT ON t TO app;\n"),
    "SQL-016": ("CREATE TABLE u (id int PRIMARY KEY, password varchar(64));\n", 1,
                "CREATE TABLE u (id int PRIMARY KEY, password_hash text, password_changed_at timestamp, password_attempts int);\n"),
    "SQL-017": ("CREATE TABLE a (id int PRIMARY KEY);\nCREATE TABLE b (id int PRIMARY KEY);\n", 1,
                "BEGIN;\nCREATE TABLE a (id int PRIMARY KEY);\nCREATE TABLE b (id int PRIMARY KEY);\nCOMMIT;\n"),
}
REL = {"SQL-017": "migrations/001_x.sql"}


def hits(src, rel="a.sql"):
    return {(f.rule_id, f.evidence[0].line_start) for f in analyze(src, REL.get(rel, rel))}


def test_every_rule_has_a_case():
    assert set(CASES) | {"SQL-018"} == set(RULES)
    assert all(r.explanation and r.fix_hint and r.title for r in RULES.values())


def test_positive_and_negative():
    for rid, (pos, line, neg) in CASES.items():
        rel = REL.get(rid, "a.sql")
        assert (rid, line) in {(f.rule_id, f.evidence[0].line_start) for f in analyze(pos, rel)}, rid
        assert rid not in {f.rule_id for f in analyze(neg, rel)}, rid


def test_sql_018_pairs_and_sections():
    up_only = [("m/001_a.up.sql", "CREATE TABLE a (id int PRIMARY KEY);"), ("m/001_a.down.sql", "DROP TABLE a;"),
               ("m/002_b.up.sql", "ALTER TABLE a ADD COLUMN x int;")]
    assert {(f.rule_id, f.evidence[0].file) for f in analyze_files(up_only)} >= {("SQL-018", "m/002_b.up.sql")}
    ok = up_only[:2]
    assert not [f for f in analyze_files(ok) if f.rule_id == "SQL-018"]
    empty = ok + [("m/003_c.up.sql", "SELECT 1;"), ("m/003_c.down.sql", "-- nothing\n")]
    assert any(f.evidence[0].file == "m/003_c.down.sql" for f in analyze_files(empty))
    goose = [("g/1.sql", "-- +goose Up\nSELECT 1;\n")]
    assert [f.rule_id for f in analyze_files(goose)] == ["SQL-018"]
    assert not analyze_files([("g/1.sql", "-- +goose Up\nSELECT 1;\n-- +goose Down\nSELECT 2;\n")])


def test_tokenizer_skips_comments_and_strings():
    src = "/* DELETE FROM t; /* nested */ still comment */\nSELECT 'it''s; DELETE FROM t' AS x; -- DELETE FROM t\nSELECT $$ DELETE FROM t; $$;\n"
    assert not analyze(src)
    assert [t.line for t in tokenize("a\n/* x\ny */ b")] == [1, 3]
    # a procedure body keeps its inner semicolons in one statement
    body = "CREATE PROCEDURE p() BEGIN\n  DELETE FROM x WHERE a = 1;\n  CASE WHEN 1 THEN SELECT 1; END CASE;\nEND;\nDELETE FROM y;\n"
    assert hits(body) == {("SQL-002", 5)}


def test_fixtures_and_check_run():
    bad = {f.rule_id for f in analyze_files([("bad.sql", (FX / "bad.sql").read_text())])}
    assert {"SQL-001", "SQL-002", "SQL-004", "SQL-005", "SQL-008", "SQL-013", "SQL-014", "SQL-016"} <= bad
    assert not analyze_files([("good.sql", (FX / "good.sql").read_text())])
    chk = SqlCheck()
    assert chk.uses_snap is False and chk.estimate(Context(), argparse.Namespace()).snap_calls == 0
    res = chk.run(Context(no_snap=True), argparse.Namespace(check_sql=str(FX), include_tests=False))
    assert res.error is None and res.stats["files"] == 6
    by_file = {f.evidence[0].file for f in res.findings}
    assert "bad.sql" in by_file and "good.sql" not in by_file and "migrations/002_more.up.sql" not in by_file
    assert chk.run(Context(), argparse.Namespace(check_sql=str(FX / "nope"))).error
