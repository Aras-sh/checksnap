"""Rule catalog for --check-sql: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
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

_RULES = [
    ("SQL-001", L, "SELECT * in a query",
     "`SELECT *` returns every column, so adding or reordering a column silently changes what callers receive, and it defeats covering indexes and wastes bandwidth.",
     "List the columns you need. `SELECT *` inside `EXISTS (...)` and `COUNT(*)` are fine and not reported."),
    ("SQL-002", H, "UPDATE or DELETE without WHERE",
     "Without a WHERE clause every row in the table is changed or removed. A forgotten filter is a classic production data-loss incident.",
     "Add a WHERE clause (check it with a SELECT first), or write `WHERE true` / use TRUNCATE to make a full-table change deliberate."),
    ("SQL-003", M, "DROP TABLE without IF EXISTS / unguarded TRUNCATE",
     "A DROP TABLE without IF EXISTS fails the whole script when the table is already gone, so the migration cannot be re-run. TRUNCATE has no guard at all and silently deletes every row.",
     "Use `DROP TABLE IF EXISTS t`; run TRUNCATE only in seed/test scripts, or inside a transaction you can roll back."),
    ("SQL-004", M, "CREATE TABLE without a primary key",
     "Tables without a primary key allow duplicate rows, break logical replication and ORMs, and make row-level updates ambiguous.",
     "Add `id BIGINT PRIMARY KEY` (or a natural/composite key). Temporary and staging tables are ignored."),
    ("SQL-005", L, "Column named *_id without an index or foreign key",
     "A `*_id` column is almost always joined or filtered on. Without an index (or a foreign key that creates one) those queries scan the whole table.",
     "Add `REFERENCES parent(id)` and `CREATE INDEX ON t (col)`. Columns already in a primary key, unique constraint or index anywhere in the scanned files are not reported."),
    ("SQL-006", M, "LIKE with a leading wildcard",
     "`LIKE '%foo'` cannot use a normal B-tree index, so the database reads every row.",
     "Anchor the pattern (`'foo%'`), or use full-text search / a trigram index (`pg_trgm`) when you really need substring search."),
    ("SQL-007", M, "NOT IN with a subquery",
     "If the subquery returns a single NULL, `NOT IN` matches nothing, and many planners handle it poorly.",
     "Use `NOT EXISTS (SELECT 1 FROM ... WHERE ...)` or a LEFT JOIN ... IS NULL."),
    ("SQL-008", L, "Implicit join (comma in FROM)",
     "`FROM a, b WHERE ...` hides the join condition in WHERE; forgetting it produces a cross join with millions of rows.",
     "Use explicit `JOIN ... ON ...`."),
    ("SQL-009", M, "ORDER BY RAND() / RANDOM()",
     "The database computes a random value for every row and sorts them all just to return a few.",
     "Pick random ids in application code, use `TABLESAMPLE`, or `WHERE id >= random_offset LIMIT 1`."),
    ("SQL-010", M, "Function applied to an indexed column in WHERE",
     "`WHERE LOWER(email) = ...` or `WHERE DATE(created_at) = ...` stops the database using the plain index on that column, so it scans the table.",
     "Compare the raw column against a range (`created_at >= x AND created_at < y`), or create an expression index (`CREATE INDEX ON t (LOWER(email))`)."),
    ("SQL-011", M, "CREATE INDEX without CONCURRENTLY (PostgreSQL)",
     "A plain CREATE INDEX on an existing PostgreSQL table blocks all writes until it finishes, which is an outage on a big table.",
     "Use `CREATE INDEX CONCURRENTLY ...` (it cannot run inside a transaction block, so put it in its own migration)."),
    ("SQL-012", M, "ADD COLUMN NOT NULL without DEFAULT",
     "Adding a NOT NULL column with no default fails as soon as the table has rows, and some engines rewrite the whole table.",
     "Add the column nullable, backfill, then `SET NOT NULL`; or give it a DEFAULT."),
    ("SQL-013", M, "Floating-point type for a money column",
     "FLOAT/REAL/DOUBLE cannot represent decimal fractions exactly (0.1 + 0.2 != 0.3), so sums drift by cents.",
     "Use `NUMERIC(12,2)` / `DECIMAL`, or store integer minor units (cents)."),
    ("SQL-014", L, "VARCHAR(255) used for most string columns",
     "255 is a habit, not a design decision. It hides real limits (emails, codes, URLs) and in some engines affects row size and index limits.",
     "Choose lengths that match the data, or use `TEXT` with a CHECK constraint where PostgreSQL is the target."),
    ("SQL-015", M, "GRANT ALL",
     "Granting every privilege breaks least privilege: a leaked application credential can drop tables or change grants.",
     "Grant only what the role needs, e.g. `GRANT SELECT, INSERT, UPDATE ON t TO app`."),
    ("SQL-016", H, "Plaintext password column",
     "A text column named `password` suggests passwords are stored as readable text; one SQL injection or backup leak exposes every account.",
     "Store a salted hash from bcrypt/argon2 and name the column `password_hash`."),
    ("SQL-017", L, "Multi-statement migration without a transaction",
     "If statement 3 of 5 fails, the first two stay applied and the schema is left half-migrated.",
     "Wrap the file in `BEGIN; ... COMMIT;` (or let the migration tool do it: goose, dbmate and Flyway are recognised and not reported)."),
    ("SQL-018", M, "Non-reversible migration in an up/down folder",
     "The folder uses up/down pairs, but this migration has no down (or an empty one), so a rollback silently skips it.",
     "Add the matching `.down.sql` that undoes the change, or document why it is irreversible."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
