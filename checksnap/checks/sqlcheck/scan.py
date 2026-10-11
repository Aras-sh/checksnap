"""Tokenizer (skips comments, keeps strings opaque) and the SQL-NNN rules for --check-sql."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import NamedTuple

from checksnap.core import Evidence, Finding

from .rules import RULES


class T(NamedTuple):
    k: str      # id | qid | str | num | op
    s: str      # text (strings: body without quotes, quoted identifiers: unquoted)
    u: str      # upper-cased text for id and op tokens, "" for str/qid/num so a literal never matches a keyword
    line: int


_ID = re.compile(r"[^\W\d][\w$]*")
_NUM = re.compile(r"\d[\w.]*")
_OP = re.compile(r"[=<>!|:~@#%^&+\-/?]+")
_DOLLAR = re.compile(r"\$([^\W\d]\w*)?\$")


def tokenize(text: str) -> list[T]:
    toks: list[T] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif text.startswith("--", i) or (c == "#" and not text[text.rfind("\n", 0, i) + 1:i].strip()):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            line += text.count("\n", i, j)
            i = j
        elif c == "'":
            esc = bool(toks) and toks[-1].u == "E" and toks[-1].line == line and text[i - 1] in "eE"
            if esc:
                toks.pop()
            j = i + 1
            while j < n:
                if esc and text[j] == "\\":
                    j += 2
                elif text[j] == "'":
                    if text[j + 1:j + 2] == "'":
                        j += 2
                    else:
                        break
                else:
                    j += 1
            body = text[i + 1:j]
            toks.append(T("str", body, "", line))
            line += body.count("\n")
            i = j + 1
        elif c in '"`':
            j = i + 1
            while j < n and not (text[j] == c and text[j + 1:j + 2] != c):
                j += 2 if text[j] == c else 1
            toks.append(T("qid", text[i + 1:j].replace(c + c, c), "", line))
            line += text.count("\n", i, j)
            i = j + 1
        elif c == "$" and (m := _DOLLAR.match(text, i)):
            j = text.find(m.group(0), m.end())
            j = n if j < 0 else j
            toks.append(T("str", "", "", line))     # ponytail: function bodies are skipped, not analysed
            line += text.count("\n", i, j)
            i = min(n, j + len(m.group(0)))
        elif m := _ID.match(text, i):
            toks.append(T("id", m.group(0), m.group(0).upper(), line))
            i = m.end()
        elif c.isdigit():
            m = _NUM.match(text, i)
            toks.append(T("num", m.group(0), "", line))
            i = m.end()
        elif m := _OP.match(text, i):
            toks.append(T("op", m.group(0), m.group(0), line))
            i = m.end()
        else:
            toks.append(T("op", c, c, line))
            i += 1
    return toks


_PROC = {"PROCEDURE", "FUNCTION", "TRIGGER"}


def statements(toks: list[T]) -> list[list[T]]:
    """Split on ';', except inside CREATE PROCEDURE/FUNCTION/TRIGGER ... BEGIN ... END bodies."""
    out: list[list[T]] = []
    cur: list[T] = []
    bal = 0
    for idx, t in enumerate(toks):
        if t.u == ";" and bal <= 0:
            if cur:
                out.append(cur)
            cur, bal = [], 0
            continue
        cur.append(t)
        if cur[0].u == "CREATE" and any(x.u in _PROC for x in cur[:10]):
            nxt = toks[idx + 1].u if idx + 1 < len(toks) else ""
            if t.u == "BEGIN" or (t.u == "CASE" and toks[idx - 1].u != "END"):
                bal += 1
            elif t.u == "END" and nxt not in ("IF", "LOOP", "WHILE", "REPEAT"):
                bal -= 1
    if cur:
        out.append(cur)
    return out


def _close(toks: list[T], i: int) -> int:
    """Index of the ')' matching the '(' at i (len(toks) when unbalanced)."""
    d = 0
    for j in range(i, len(toks)):
        if toks[j].u == "(":
            d += 1
        elif toks[j].u == ")":
            d -= 1
            if d == 0:
                return j
    return len(toks)


def _split(toks: list[T], lo: int, hi: int) -> list[list[T]]:
    parts, cur, d = [], [], 0
    for t in toks[lo:hi]:
        if t.u == "(":
            d += 1
        elif t.u == ")":
            d -= 1
        if t.u == "," and d == 0:
            parts.append(cur)
            cur = []
        else:
            cur.append(t)
    parts.append(cur)
    return parts


def _name(toks: list[T], i: int) -> tuple[str | None, int]:
    """Possibly schema-qualified name at i -> (last part lower-cased, next index)."""
    last = None
    while i < len(toks) and toks[i].k in ("id", "qid"):
        last = toks[i].s.lower()
        i += 1
        if i + 1 < len(toks) and toks[i].u == "." and toks[i + 1].k in ("id", "qid"):
            i += 1
        else:
            break
    return last, i


def _create_table(st: list[T]):
    i, temp = 1, False
    while i < len(st) and st[i].u in ("OR", "REPLACE", "GLOBAL", "LOCAL", "UNLOGGED", "TEMP", "TEMPORARY"):
        temp |= st[i].u in ("TEMP", "TEMPORARY")
        i += 1
    if st[0].u != "CREATE" or i >= len(st) or st[i].u != "TABLE":
        return None
    i += 1
    if [t.u for t in st[i:i + 3]] == ["IF", "NOT", "EXISTS"]:
        i += 3
    name, i = _name(st, i)
    if not name or i >= len(st) or st[i].u != "(":
        return None
    return name, temp, _split(st, i + 1, _close(st, i))


_CONSTRAINT = {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX", "KEY", "FULLTEXT", "SPATIAL", "EXCLUDE", "LIKE", "PERIOD"}
_STOP = {"DEFAULT", "CHECK", "REFERENCES", "NOT", "NULL", "PRIMARY", "UNIQUE"}


def _keys(item: list[T]):
    """PK / UNIQUE / FK / INDEX clauses in one table item -> [(kind, plain_cols|None, [(fn, col)])]."""
    out = []
    for i, t in enumerate(item):
        if t.k != "id":
            continue
        kind, j = None, 0
        nxt = item[i + 1].u if i + 1 < len(item) else ""
        if t.u == "PRIMARY" and nxt == "KEY":
            kind, j = "pk", i + 2
        elif t.u == "FOREIGN" and nxt == "KEY":
            kind, j = "fk", i + 2
        elif t.u == "UNIQUE":
            kind, j = "unique", i + 1
        elif t.u in ("INDEX", "KEY") and (i == 0 or item[i - 1].u in ("ADD", "FULLTEXT", "SPATIAL", "UNIQUE")):
            kind, j = "index", i + 1
        if not kind:
            continue
        k = j
        while k < len(item) and k - j < 4 and item[k].k in ("id", "qid") and item[k].u not in _STOP:
            k += 1
        if k < len(item) and item[k].u == "(":
            plain, funcs = [], []
            for part in _split(item, k + 1, _close(item, k)):
                if not part or part[0].k not in ("id", "qid"):
                    continue
                if part[0].k == "id" and len(part) > 1 and part[1].u == "(":
                    inner = next((x.s.lower() for x in part[2:] if x.k in ("id", "qid")), None)
                    funcs.append((part[0].u.lower(), inner))
                else:
                    plain.append(part[0].s.lower())
            out.append((kind, plain, funcs))
        else:
            out.append((kind, None, []))
    return out


def _alter_actions(st: list[T]):
    """ALTER TABLE t ADD ... -> (table, [action tokens after ADD])."""
    if [t.u for t in st[:2]] != ["ALTER", "TABLE"]:
        return None, []
    i = 2
    while i < len(st) and st[i].u in ("IF", "EXISTS", "ONLY"):
        i += 1
    name, i = _name(st, i)
    acts = []
    for a in _split(st, i, len(st)):
        if a and a[0].u == "ADD":
            acts.append(a[1:])
    return name, acts


_MONEY = {"price", "amount", "cost", "balance", "total", "subtotal", "salary", "fee", "fees", "money", "revenue", "payment",
          "tax", "discount", "wage", "budget", "charge", "refund", "income", "profit"}
_NOT_MONEY = {"count", "ratio", "rate", "percent", "pct", "score", "weight", "qty", "quantity", "number", "num", "id", "flag", "date",
              "at", "type", "status", "name", "code", "method", "limit"}
_FLOATS = {"FLOAT", "REAL", "DOUBLE", "FLOAT4", "FLOAT8"}
_NOT_PW = {"hash", "hashed", "digest", "salt", "encrypted", "bcrypt", "argon", "argon2", "crypt", "reset", "expires", "expiry",
           "changed", "updated", "at", "required", "policy", "attempts", "count", "last", "max", "min", "length", "hint", "token"}
_TEXTS = {"VARCHAR", "TEXT", "CHAR", "CHARACTER", "NVARCHAR", "NCHAR", "CITEXT", "STRING", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT"}
_FROM_END = {"WHERE", "GROUP", "ORDER", "HAVING", "LIMIT", "UNION", "INTERSECT", "EXCEPT", "WINDOW", "FOR", "RETURNING", "OFFSET",
             "FETCH", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL", "ON", "USING", "SET"}
_WHERE_END = {"GROUP", "ORDER", "HAVING", "LIMIT", "UNION", "INTERSECT", "EXCEPT", "WINDOW", "RETURNING", "FETCH", "OFFSET"}
_WRAP_FN = {"LOWER", "UPPER", "DATE", "YEAR", "MONTH", "DAY", "HOUR", "TRIM", "LTRIM", "RTRIM", "SUBSTR", "SUBSTRING", "DATE_TRUNC",
            "TO_CHAR", "TO_DATE", "LENGTH", "DATE_FORMAT", "UNIX_TIMESTAMP"}
_CMP = {"=", "<", ">", "<=", ">=", "<>", "!=", "IN", "LIKE", "ILIKE", "BETWEEN"}
_MUTATING = {"CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "RENAME"}
_PG = re.compile(r"::|\bserial\b|\bbigserial\b|create\s+extension|\$\$|\bjsonb\b|\btimestamptz\b|plpgsql|\bilike\b|gen_random_uuid|\bconcurrently\b|\breturning\b", re.I)
_MY = re.compile(r"`|auto_increment|\bengine\s*=|\bunsigned\b", re.I)
_TOOLS = re.compile(r"\+goose|migrate:(up|down)|\+migrate|flyway|liquibase|sqitch|transaction", re.I)
_DOWN_MARK = re.compile(r"^\s*--\s*(\+goose\s+down|\+migrate\s+down|migrate:down)", re.I | re.M)
_UP_MARK = re.compile(r"^\s*--\s*(\+goose\s+up|\+migrate\s+up|migrate:up)", re.I | re.M)
_UPDOWN = re.compile(r"^(?P<base>.+?)[._-](?P<d>up|down)$", re.I)
_SEEDY = re.compile(r"seed|reset|fixture|truncate|clean", re.I)


def _words(name: str) -> set[str]:
    return set(re.split(r"[_\W]+", re.sub(r"(?<=[a-z])(?=[A-Z])", "_", name).lower()))


class _Scan:
    def __init__(self, proj_pg: bool):
        self.proj_pg = proj_pg
        self.out: list[Finding] = []
        self._seen: set[tuple] = set()
        self.indexed: set[tuple[str, str]] = set()      # (table, col): pk / unique / index
        self.covered: set[tuple[str, str]] = set()      # indexed + foreign keys
        self.idx_cols: set[str] = set()
        self.func_idx: set[tuple[str, str | None]] = set()
        self.cand005: list[tuple[str, int, str, str, str]] = []
        self.cand010: list[tuple[str, int, str, str, str]] = []

    def add(self, rid: str, rel: str, line: int, snippet: str) -> None:
        if (rid, rel, line) in self._seen:
            return
        self._seen.add((rid, rel, line))
        r = RULES[rid]
        self.out.append(Finding("sql", rid, r.severity, r.title, r.explanation, [Evidence(rel, line, line, snippet.strip()[:160])],
                                source="static", fix_hint=r.fix_hint))

    def record_keys(self, table: str, keys, colname: str | None = None) -> None:
        for kind, plain, funcs in keys:
            cols = plain if plain is not None else ([colname] if colname else [])
            for c in cols:
                self.covered.add((table, c))
                if kind != "fk":
                    self.indexed.add((table, c))
                    self.idx_cols.add(c)
            self.func_idx.update(funcs)

    def file(self, rel: str, text: str) -> None:
        lines = text.splitlines()
        snip = lambda n: lines[n - 1] if 0 < n <= len(lines) else ""  # noqa: E731
        name = PurePosixPath(rel).stem.lower()
        m = _DOWN_MARK.search(text)
        down_from = text.count("\n", 0, m.start()) + 2 if m else (1 if re.search(r"(^|[._-])down$|^down[._-]", name) else 10**9)
        pgm, myl = bool(_PG.search(text)), bool(_MY.search(text))
        is_pg = (pgm and not myl) or (not pgm and not myl and self.proj_pg)
        sts = statements(tokenize(text))
        created: set[str] = set()
        varchars = [0, 0, 0]        # total, 255, first line of a 255
        mutating: list[int] = []
        txn = False
        for st in sts:
            first, line = st[0].u, st[0].line
            is_down = line >= down_from
            txn |= first in ("BEGIN", "START", "COMMIT")
            if first in _MUTATING and not is_down:
                mutating.append(line)
            self.query_rules(st, rel, snip)
            if first in ("UPDATE", "DELETE") and not (len(st) > 1 and st[1].u == "STATISTICS"):
                d = 0
                has_where = False
                for t in st:
                    d += (t.u == "(") - (t.u == ")")
                    has_where |= t.u == "WHERE" and d == 0
                if not has_where:
                    self.add("SQL-002", rel, line, snip(line))
            if first == "DROP" and len(st) > 1 and st[1].u == "TABLE" and [t.u for t in st[2:4]] != ["IF", "EXISTS"] and not is_down:
                self.add("SQL-003", rel, line, snip(line))
            if first == "TRUNCATE" and not is_down and not _SEEDY.search(name):
                self.add("SQL-003", rel, line, snip(line))
            if first in ("SELECT", "UPDATE", "DELETE", "WITH"):
                self.where_funcs(st, rel, snip)
            if first == "GRANT" and len(st) > 1 and st[1].u == "ALL":
                self.add("SQL-015", rel, line, snip(line))
            if first == "CREATE":
                self.create_index(st, rel, snip, created, is_pg)
            ct = _create_table(st)
            if ct:
                table, temp, items = ct
                created.add(table)
                has_pk = False
                for item in items:
                    if not item:
                        continue
                    keys = _keys(item)
                    has_pk |= any(k[0] == "pk" for k in keys)
                    if item[0].u in _CONSTRAINT:
                        self.record_keys(table, keys)
                    else:
                        self.column(rel, table, item, keys, True, False, snip, varchars)
                if not has_pk and not temp and not re.match(r"(tmp|temp|stg|staging)", table) and not any(i and i[0].u == "LIKE" for i in items):
                    self.add("SQL-004", rel, line, snip(line))
            table, acts = _alter_actions(st)
            for a in acts:
                if a and a[0].u == "COLUMN":
                    a = a[1:]
                if [t.u for t in a[:3]] == ["IF", "NOT", "EXISTS"]:
                    a = a[3:]
                if not a or a[0].u == "(":
                    continue
                keys = _keys(a)
                if a[0].u in _CONSTRAINT:
                    self.record_keys(table, keys)
                else:
                    self.column(rel, table, a, keys, False, table in created, snip, varchars)
        if varchars[1] >= 3 and varchars[1] / varchars[0] >= 0.6:
            self.add("SQL-014", rel, varchars[2], snip(varchars[2]))
        if len(mutating) >= 2 and not txn:
            if (not myl and not _TOOLS.search(text) and "CONCURRENTLY" not in text.upper()
                    and down_from > 10**8 and _is_migration(rel)):
                self.add("SQL-017", rel, mutating[0], snip(mutating[0]))

    def query_rules(self, st: list[T], rel: str, snip) -> None:
        n = len(st)
        for i, t in enumerate(st):
            nx = st[i + 1] if i + 1 < n else T("op", "", "", 0)
            if t.u == "*" and i and st[i - 1].u in ("SELECT", "DISTINCT"):
                exists = i >= 3 and st[i - 2].u == "(" and st[i - 3].u == "EXISTS"
                if not exists and not (nx.u == "FROM" and i + 2 < n and st[i + 2].u == "("):
                    self.add("SQL-001", rel, t.line, snip(t.line))
            elif t.u in ("LIKE", "ILIKE"):
                lit = nx if nx.k == "str" else (st[i + 3] if nx.u == "CONCAT" and i + 3 < n and st[i + 2].u == "(" else None)
                if lit is not None and lit.k == "str" and lit.s.startswith("%"):
                    self.add("SQL-006", rel, t.line, snip(t.line))
            elif t.u == "NOT" and nx.u == "IN" and i + 3 < n and st[i + 2].u == "(" and st[i + 3].u in ("SELECT", "("):
                self.add("SQL-007", rel, t.line, snip(t.line))
            elif t.u == "ORDER" and nx.u == "BY":
                d = 0
                for j in range(i + 2, n):
                    u = st[j].u
                    d += (u == "(") - (u == ")")
                    if d < 0 or u in ("LIMIT", "OFFSET", "FETCH", "UNION"):
                        break
                    if u in ("RAND", "RANDOM", "NEWID") and j + 1 < n and st[j + 1].u == "(":
                        self.add("SQL-009", rel, st[j].line, snip(st[j].line))
                        break
        ln = self.implicit_join(st)
        if ln:
            self.add("SQL-008", rel, ln, snip(ln))

    @staticmethod
    def implicit_join(st: list[T]) -> int | None:
        if st[0].u in ("DELETE", "REVOKE", "COPY", "GRANT") or not any(t.u == "SELECT" for t in st):
            return None
        for i, t in enumerate(st):
            if t.u != "FROM" or (i and st[i - 1].u == "DISTINCT"):
                continue
            d = 0
            for j in range(i + 1, len(st)):
                u = st[j].u
                if u == "(":
                    d += 1
                elif u == ")":
                    if d == 0:
                        break
                    d -= 1
                elif d == 0:
                    if u in _FROM_END:
                        break
                    if u == "," and j + 1 < len(st):
                        nx = st[j + 1]
                        func = nx.k == "id" and j + 2 < len(st) and st[j + 2].u == "("
                        if nx.u != "LATERAL" and not func:
                            return st[j].line
        return None

    def where_funcs(self, st: list[T], rel: str, snip) -> None:
        n = len(st)
        for i, t in enumerate(st):
            if t.u != "WHERE":
                continue
            d = 0
            for j in range(i + 1, n):
                u = st[j].u
                d += (u == "(") - (u == ")")
                if d < 0 or (d == 0 and u in _WHERE_END):
                    break
                if u in _WRAP_FN and st[j].k == "id" and j + 1 < n and st[j + 1].u == "(":
                    k = j + 2
                    while k + 1 < n and st[k].k in ("id", "qid") and st[k + 1].u == ".":
                        k += 2
                    if k + 1 < n and st[k].k in ("id", "qid") and st[k + 1].u == ")" and k + 2 < n and st[k + 2].u in _CMP:
                        self.cand010.append((rel, st[j].line, st[k].s.lower(), u.lower(), snip(st[j].line)))

    def create_index(self, st: list[T], rel: str, snip, created: set[str], is_pg: bool) -> None:
        i = 1
        if st[i].u == "UNIQUE" if len(st) > 1 else False:
            i += 1
        if i >= len(st) or st[i].u != "INDEX":
            return
        i += 1
        conc = i < len(st) and st[i].u == "CONCURRENTLY"
        j = i
        while j < len(st) and st[j].u != "ON":
            j += 1
        if j >= len(st):
            return
        j += 1
        only = j < len(st) and st[j].u == "ONLY"
        table, j = _name(st, j + only)
        if not table:
            return
        while j < len(st) and st[j].u != "(":
            j += 1
        if j < len(st):
            self.record_keys(table, _keys([T("id", "INDEX", "INDEX", 0)] + st[j:]))
        if is_pg and not conc and not only and table not in created:
            self.add("SQL-011", rel, st[0].line, snip(st[0].line))

    def column(self, rel: str, table: str, item: list[T], keys, in_create: bool, created_here: bool, snip, varchars) -> None:
        if item[0].k not in ("id", "qid"):
            return
        name, rest = item[0].s, item[1:]
        line = item[0].line
        us = [t.u for t in rest]
        typ = us[0] if us else ""
        self.record_keys(table, [k for k in keys if k[1] is None], name.lower())
        if "REFERENCES" in us:
            self.covered.add((table, name.lower()))
        low = name.lower()
        if low.endswith("_id") and low != "id":
            self.cand005.append((rel, line, table, low, snip(line)))
        w = _words(name)
        if w & _MONEY and not w & _NOT_MONEY and typ in _FLOATS:
            self.add("SQL-013", rel, line, snip(line))
        if w & {"password", "passwd", "pwd", "passphrase"} and not w & _NOT_PW and typ in _TEXTS:
            self.add("SQL-016", rel, line, snip(line))
        if typ in ("VARCHAR", "NVARCHAR") or (typ == "CHARACTER" and len(us) > 1 and us[1] == "VARYING"):
            if "(" in us[:4]:
                varchars[0] += 1
                if any(t.k == "num" and t.s == "255" for t in rest[:5]):
                    varchars[1] += 1
                    varchars[2] = varchars[2] or line
        if not in_create and not created_here:
            if ("NOT", "NULL") in zip(us, us[1:]) and not set(us) & {"DEFAULT", "GENERATED", "AUTO_INCREMENT", "AUTOINCREMENT", "IDENTITY"} \
                    and not typ.endswith("SERIAL"):
                self.add("SQL-012", rel, line, snip(line))

    def finish(self) -> None:
        for rel, line, table, col, sn in self.cand005:
            if (table, col) not in self.covered:
                self.add("SQL-005", rel, line, sn)
        for rel, line, col, fn, sn in self.cand010:
            if col in self.idx_cols and (fn, col) not in self.func_idx:
                self.add("SQL-010", rel, line, sn)


def _is_migration(rel: str) -> bool:
    p = PurePosixPath(rel.lower())
    return any(x in ("migrations", "migrate", "migration") for x in p.parts[:-1]) or bool(re.match(r"(v?\d{3,}|\d{4}-\d\d-\d\d)", p.name))


def _dir_rules(sc: _Scan, files: list[tuple[str, str]]) -> None:
    """SQL-018: up/down pairs in one folder, and goose/dbmate style up-only files."""
    folders: dict[str, dict[str, dict[str, str]]] = {}
    for rel, text in files:
        p = PurePosixPath(rel)
        if _UP_MARK.search(text) and not _DOWN_MARK.search(text):
            sc.add("SQL-018", rel, 1, "up migration without a down section")
        m = _UPDOWN.match(p.stem)
        if m:
            folders.setdefault(str(p.parent), {}).setdefault(m["base"].lower(), {})[m["d"].lower()] = rel
    for pairs in folders.values():
        if not any(len(v) == 2 for v in pairs.values()):
            continue
        for v in pairs.values():
            if "down" not in v:
                sc.add("SQL-018", v["up"], 1, "no matching .down.sql")
    body = dict(files)
    for pairs in folders.values():
        if not any(len(v) == 2 for v in pairs.values()):
            continue
        for v in pairs.values():
            if "down" in v and not statements(tokenize(body[v["down"]])):
                sc.add("SQL-018", v["down"], 1, "empty down migration")


def analyze_files(files: list[tuple[str, str]]) -> list[Finding]:
    pg = any(_PG.search(t) for _, t in files)
    my = any(_MY.search(t) for _, t in files)
    sc = _Scan(pg and not my)
    for rel, text in files:
        sc.file(rel, text)
    sc.finish()
    _dir_rules(sc, files)
    return sc.out


def analyze(text: str, rel: str = "a.sql") -> list[Finding]:
    return analyze_files([(rel, text)])
