# Security & Code Review Findings

> Review date: 2026-07-18 · Scope: `backend/`, `frontend/`, `investigator-stack.yaml`, `docker-compose.yml`, `.env`
> Severity order: Critical → High → Medium → Low. Each finding lists the location, a concrete failure scenario, and a suggested fix.

## Status legend
- [ ] Open
- [x] Fixed / mitigated

---

## CRITICAL

### [ ] C1 — Live AWS access keys committed in `.env`
**File:** `.env:10-11`

Real, long-lived IAM credentials are present in the repo:

```
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

There is **no `.gitignore`**, so `.env` will be committed the moment `git init` / `git add` happens (`AUTHENTICATION.md` says "keep it out of version control" but nothing enforces it). The file also pins a real results bucket (`ATHENA_OUTPUT_LOCATION=s3://.../results/`) and a static `AUTH_TOKEN`.

**Fix:** Rotate/revoke these keys now — an `AKIA...` long-lived pair must be treated as compromised. Delete them from `.env`, add a `.gitignore` containing `.env`, and rely on the `~/.aws` profile or short-lived STS credentials per `AUTHENTICATION.md`.

---

## HIGH

### [ ] H1 — Max time-window cap (constraint #3) is never enforced in code
**File:** `backend/main.py` (`MAX_DAYS` / `ALLOWED_TIME_RANGE_MAX_DAYS`, `validate_sql`)

`MAX_DAYS` appears **only inside the LLM prompt**. `validate_sql()` never checks the actual window. Because the user can freely edit the SQL in the approval modal and `execute-sql` re-validates with the same `validate_sql()`, anyone can submit:

```sql
SELECT * FROM cloudtrail_logs
WHERE eventtime >= to_iso8601(current_timestamp - interval '3650' day)
```

and it passes. The "mandatory max-window cap" is advisory only.

**Fix:** Parse the `eventtime`/`dt` (and VPC `start`/`end`) predicate and reject windows exceeding `MAX_DAYS`, or reject when the lower bound can't be statically determined.

### [ ] H2 — Time-filter guardrail is trivially satisfied and does not enforce partition pruning
**File:** `backend/main.py` `validate_sql` (WHERE column check)

The check only requires that a time column name appears somewhere inside *any* `WHERE` in the statement. Bypasses that still scan the whole table:

- `WHERE eventtime IS NOT NULL` — passes, no pruning.
- `WHERE eventname='x' AND eventtime = eventtime` — passes.
- **Subquery bypass:** `find_all(exp.Where)` is recursive, so a time bound in an inner subquery satisfies the check even when the **outer** full-table scan has no time bound.

Also, `eventtime` is a plain string column, **not** a partition key (`account`/`region`/`dt` are). Filtering on `eventtime` alone does not prune partitions — Athena scans all objects. The few-shot examples only use `eventtime`, so generated queries will full-scan every time, undermining constraints #3/#5. In deployed environments the workgroup `BytesScannedCutoffPerQuery` is the only real backstop (see H3 for why it's absent locally).

> Note: the Phase 5 VPC `start`/`end` filter shares the same weakness — consistent with the existing design, not a new regression.

**Fix:** Require a real range comparison (`>=`/`>`/`BETWEEN`) on the time column in the *top-level* WHERE (not nested), and strongly prefer requiring a `dt` partition bound. Validate the outer query's WHERE specifically rather than any WHERE anywhere.

### [ ] H3 — `BYTES_SCANNED_CUTOFF` is passed as env but never applied in code
**File:** `backend/main.py` (no reference), `docker-compose.yml`, `.env`, `investigator-stack.yaml`

`main.py` never reads `BYTES_SCANNED_CUTOFF`. In production the Athena **workgroup** enforces it, so prod is covered. But local/VM dev runs against the `primary` workgroup, which has **no** cutoff. Combined with real credentials + real results bucket in `.env` and the unbounded-window gaps (H1/H2), a single question against the real account can trigger an arbitrarily large, expensive Athena scan.

**Fix:** In `execute_sql`, when the target workgroup does not enforce a cutoff, apply a client-side guard (e.g. poll `DataScannedInBytes`, or use a dedicated local workgroup with a cutoff). Do not run local dev against `primary` with production credentials.

---

## MEDIUM

### [ ] M1 — Legitimate CTE queries are falsely rejected; table whitelist matches bare name
**File:** `backend/main.py` `validate_sql` (table whitelist)

A CTE reference (`WITH x AS (SELECT ... FROM cloudtrail_logs) SELECT * FROM x`) surfaces `x` as an `exp.Table`, so `x` is not in the whitelist and the query is rejected — valid read-only CTEs are unusable. Separately, the whitelist compares only the bare table name, so `otherdb.cloudtrail_logs` would pass (IAM `glue:GetTable` scoping is the actual backstop, which is why this is Medium).

**Fix:** Collect CTE names (`exp.CTE`) and exclude them from the table set before diffing; consider validating the DB qualifier too.

### [ ] M2 — Errors from Bedrock/Athena are echoed to the client
**File:** `backend/main.py` (Bedrock/Athena `HTTPException` messages, `StateChangeReason`)

Raw provider messages are returned to the SPA. Athena failure reasons can leak schema/column names; Bedrock errors can leak model/region config.

**Fix:** Return a generic message to the client and log the detail server-side.

### [ ] M3 — Unauthenticated `/api/health` leaks configuration
**File:** `backend/main.py` `health()`

Returns `model` and `database.table(s)` with no auth — minor recon aid.

**Fix:** Either require auth or strip identifying fields.

### [ ] M4 — `auth_token()` cached forever via `lru_cache`
**File:** `backend/main.py` `auth_token()`

The token is fetched from Secrets Manager once per warm Lambda and cached for the container's lifetime. After a secret rotation, warm containers keep accepting the old token (and reject the new one) until a cold start.

**Fix:** Add a short TTL cache, or fetch per request (cheap relative to Bedrock/Athena).

---

## LOW

### [ ] L1 — Wildcard CORS everywhere
**File:** `backend/main.py`, `investigator-stack.yaml`, `backend/mock_server.py`

`allow_origins=["*"]`. Auth is a bearer token in `localStorage` (not cookies) and credentials aren't allowed, so cross-origin token theft isn't directly enabled, but any site can drive the API if it obtains the token.

**Fix:** Pin to the CloudFront domain.

### [ ] L2 — Summarization re-runs on every successful results poll (cost)
**File:** `backend/main.py` `get_results()`

`/api/results/{id}` re-fetches rows and re-invokes Bedrock every time it's called for a `SUCCEEDED` query. Any repeat GET incurs another Bedrock call with no caching.

**Fix:** Cache the summary per `execution_id`, or make summarization a separate explicit call.

### [ ] L3 — `--reload` / dev server in the container image
**File:** `backend/Dockerfile`, `docker-compose.yml`

The Dockerfile `CMD` uses `uvicorn --reload` (dev-only). Fine for local, but this image should not be used as-is for a non-dev container target. (Lambda uses the `Mangum` handler, so this only affects container/VM runs.)

**Fix:** Use a production command for non-dev image targets.

### [ ] L4 — Mock server uses string-matching and non-constant-time auth
**File:** `backend/mock_server.py`

`"select" in sql.lower()` and `token == AUTH_TOKEN`. Acceptable for a local mock, but worth a comment noting it deliberately does **not** mirror the real parse-based guardrail, so it can't be mistaken for a security control.

**Fix:** Add a clarifying comment.

---

## Constraints that hold up (verified correct)
- **HITL / no auto-execute (#2):** `generate-sql` and `execute-sql` are genuinely separate; the SPA shows the SQL in an approval modal and only runs on explicit approve. `execute-sql` re-validates the (possibly edited) SQL.
- **Parse-based SELECT-only (#1):** `validate_sql` uses `sqlglot.parse` (not string matching), rejects multi-statement input, forbids `Insert/Update/Delete/Create/Drop/Alter/Merge/Command`, requires `Select`/`Union`. Comment-based and `;`-stacking bypasses handled. One gap: table-name-only whitelisting (M1), mitigated by IAM.
- **Grounding (#4):** `_summarize` sends only the returned rows; the system prompt forbids inventing data; empty result sets short-circuit to a fixed message.
- **Least-privilege IAM / no always-on compute (#5, #6):** Bedrock scoped to the model ARN, Athena to the workgroup, Glue to the specific DB/table(s), S3 read-only on source buckets + RW only on the results bucket. Partition projection (no crawler), workgroup `BytesScannedCutoffPerQuery`, results-bucket 7-day lifecycle, S3 public access blocked, CloudFront OAC — all present.

---

## Recommended priority
1. **C1** — revoke the leaked keys immediately.
2. **H1 / H2 / H3** — the time-window / partition / bytes-scanned guardrails are weaker than the design claims; currently only prod's workgroup byte cutoff meaningfully constrains scan cost.
3. **M1** — restores CTE support and tightens the table whitelist.
