# MIGRATIONS — schema evolution for the adversarial platform

The platform has **two independently-versioned schema surfaces**. Keep them distinct — a
reviewer should never confuse one for the other:

| Surface | What it is | Where it lives | Versioning authority |
| --- | --- | --- | --- |
| **Inter-agent message contracts** | The typed JSON payloads passed Orchestrator→RedTeam→Judge→Documentation | `/contracts/*.vN.json` | [`contracts/CHANGELOG.md`](contracts/CHANGELOG.md) — breaking change ⇒ new `*.vN.json` file |
| **Exploit database** | The regression store of confirmed exploits | `redteam/store.py` (sqlite) | this document |

This file governs the **exploit database**.

## Current exploit-DB schema (v1)

`redteam/store.py` → `SCHEMA_VERSION = 1`. Table `exploit`:

| Column | Notes |
| --- | --- |
| `id` | PK, autoincrement |
| `category`, `reproduction_seed` | `UNIQUE(category, reproduction_seed)` — the dedup key; one row per attack, not per run |
| `severity`, `provenance` | `seeded` vs `mutation_discovered` |
| `status` | `open` / `fixed` / `regressed` (+ `pending_review` for critical) |
| `first_seen_sha`, `fixed_in_sha`, `last_verified_sha`, `last_verified_verdict`, `last_verified_ts` | provenance + regression trail |
| `schema_version` | the schema version the row was written under |

First-run is handled by `CREATE TABLE IF NOT EXISTS`.

## Migration approach — additive, versioned, zero data loss

Schema changes are applied as an **ordered list of forward migrations**, keyed by version,
run once at store open. The rule that guarantees no data loss: **only add columns, always with
a safe `DEFAULT`, never `DROP` in a forward migration** (deprecate a column by leaving it in
place). Additive columns with defaults mean every existing row backfills automatically.

```python
# redteam/store.py (sketch)
SCHEMA_VERSION = 2  # bumped when a migration is added

_MIGRATIONS = [
    # (target_version, SQL applied to reach it)
    (2, "ALTER TABLE exploit ADD COLUMN cvss_score REAL NOT NULL DEFAULT 0.0"),
    # (3, "ALTER TABLE exploit ADD COLUMN owasp_cell TEXT NOT NULL DEFAULT ''"),
]

def _migrate(conn):
    cur = conn.execute("PRAGMA user_version").fetchone()[0]
    for target, sql in _MIGRATIONS:
        if cur < target:
            conn.execute(sql)              # additive column, safe default -> existing rows backfill
            conn.execute(f"PRAGMA user_version = {target}")
            cur = target
    conn.commit()
```

`_migrate(conn)` runs in `ExploitStore.__init__` immediately after the `CREATE TABLE IF NOT
EXISTS`. On a fresh DB the table is created at the latest shape and `user_version` is stamped;
on an existing DB the loop applies only the gaps between the stored `user_version` and
`SCHEMA_VERSION`.

## Worked example — add `cvss_score` to the vulnerability-report format

1. Bump `SCHEMA_VERSION` to `2`.
2. Append `(2, "ALTER TABLE exploit ADD COLUMN cvss_score REAL NOT NULL DEFAULT 0.0")` to
   `_MIGRATIONS`.
3. On next open, existing findings gain `cvss_score = 0.0` (no row rewritten, no data lost); new
   findings populate it. The Documentation Agent reads the column if present and omits the CVSS
   line when it is at the default — so old and new reports both render correctly.

## Safety & rollback

- Migrations are **forward-only and additive**, so a partially-migrated DB is always readable by
  the newer code (defaults cover missing values).
- Because columns are never dropped, rolling the **code** back one version still reads the DB —
  the extra column is simply ignored by the older reader.
- The store is small and rebuildable from `evals/adversarial/` + a live re-verify, so the
  ultimate fallback is a clean rebuild; the migration path exists so that day-to-day schema
  growth never requires one.
