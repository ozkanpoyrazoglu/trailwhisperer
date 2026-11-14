"""MCP server: Claude writes the SQL, this process decides whether it runs.

Tools
  get_investigation_context  schema crib-sheet, rules and examples (read once)
  check_query                guardrail + scan estimate; touches S3 metadata only
  run_query                  re-checks everything, then runs on Athena
  get_results                fetch a query this server started that outlived run_query

Human approval is the MCP client's tool-permission prompt: leave `run_query` off
your allow-list and every execution waits for a person. `run_query` requires the
estimate as an argument, so the prompt shows the SQL *and* what it will scan.
"""

import functools
import time

import boto3
from botocore.exceptions import ClientError
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import estimate as est
from . import grounding, guardrail
from .config import Settings, load

INSTRUCTIONS = """\
TrailWhisperer investigates AWS CloudTrail (API activity) and VPC Flow Logs (network traffic) with Athena.
Workflow, every time:
1. Call get_investigation_context once per conversation and follow its rules exactly.
2. Write ONE read-only Athena (Trino) SELECT. Every log-table SELECT must filter the `dt` partition.
3. Call check_query. If it is rejected, fix the SQL and check again.
4. Show the user the SQL, a one-line plain-English explanation and the estimated scan/cost.
5. Call run_query with the same SQL and the estimated_scan_mb from check_query.
6. Answer ONLY from the rows returned. Never invent events. Report identities, ARNs and IPs verbatim.
"""

mcp = MCPServer(name="trailwhisperer", instructions=INSTRUCTIONS)

# Executions started by this process; get_results refuses anything else so the
# model can't read other people's query results from the same workgroup.
_OWN_EXECUTIONS: set[str] = set()


@functools.lru_cache(maxsize=1)
def settings() -> Settings:
    return load()


@functools.lru_cache(maxsize=1)
def _session():
    return boto3.Session(region_name=settings().region)


def _athena():
    return _session().client("athena")


def _s3():
    return _session().client("s3")


@functools.lru_cache(maxsize=1)
def layouts() -> dict[str, est.TableLayout]:
    """Partition layout for each log table that actually exists in Glue."""
    s, glue = settings(), _session().client("glue")
    out = {}
    for name in (s.cloudtrail_table, s.vpc_table):
        try:
            table = glue.get_table(DatabaseName=s.database, Name=name)["Table"]
        except glue.exceptions.EntityNotFoundException:
            continue
        out[name.lower()] = est.TableLayout.from_glue(table)
    if not out:
        raise RuntimeError(f"no TrailWhisperer tables found in Glue database `{s.database}`; run `trailwhisperer-local init`")
    return out


def _policy() -> guardrail.Policy:
    s = settings()
    return guardrail.Policy(database=s.database, time_partitioned=frozenset(layouts()), max_days=s.max_days)


def _check(sql: str) -> dict:
    sql = sql.strip().rstrip(";").strip()
    ok, reason = guardrail.validate(sql, _policy())
    if not ok:
        return {"allowed": False, "reason": reason, "stage": "guardrail"}
    e = est.estimate(sql, layouts(), _s3())
    result = {"allowed": True, "sql": sql, **e.as_dict()}
    limit = settings().max_scan_bytes
    if e.bytes is None:
        # Fail closed: a query we can't size doesn't run.
        result.update(allowed=False, stage="estimate", reason=f"could not estimate the scan: {e.note}")
    elif e.bytes > limit:
        result.update(allowed=False, stage="scan-limit",
                      reason=f"estimated scan {e.bytes / 1024**2:.1f} MB exceeds the {limit / 1024**2:.0f} MB limit; "
                             "narrow the dt window or filter by region/account")
    return result


# --- Tools ----------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(title="Schema and rules", readOnlyHint=True, idempotentHint=True))
def get_investigation_context() -> str:
    """Tables, columns, SQL rules and worked examples. Call once before writing SQL."""
    s, tables = settings(), layouts()
    ct, vpc = s.cloudtrail_table, s.vpc_table
    parts = [
        f"Database: {s.database}. Whitelisted tables: {', '.join(f'`{t}`' for t in tables)}.",
        f"Maximum time window: {s.max_days} days. Queries estimated above "
        f"{s.max_scan_bytes / 1024**2:.0f} MB are refused. At most {s.max_rows} rows come back, so aggregate or LIMIT.",
        "RULES: exactly one read-only SELECT; every SELECT that reads a log table filters `dt` in its own WHERE, "
        "in AND context, as dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d'); also filter the "
        "event timestamp with the same N; to correlate CloudTrail with VPC Flow Logs use UNION ALL with matching "
        "columns, never a JOIN; single quotes for string literals. Filtering the `region` or `account` partition "
        "columns reduces the scan.",
        grounding.NO_REDACTION,
    ]
    if ct.lower() in tables:
        parts.append(f"CLOUDTRAIL (`{ct}`) COLUMNS:\n{grounding.CRIB}")
        parts.append(f"Projected regions: {', '.join(tables[ct.lower()].regions)}.")
    if vpc.lower() in tables:
        parts.append(f"VPC FLOW LOGS (`{vpc}`) COLUMNS:\n{grounding.VPC_CRIB}")
    parts.append("EXAMPLES:\n" + grounding.fewshot(ct, vpc))
    return "\n\n".join(parts)


@mcp.tool(annotations=ToolAnnotations(title="Check SQL and estimate scan", readOnlyHint=True, idempotentHint=True))
def check_query(sql: str) -> dict:
    """Validate SQL against the guardrail and estimate the bytes Athena would scan
    (from the real S3 object sizes of the partitions it touches). Runs nothing on Athena."""
    return _check(sql)


@mcp.tool(annotations=ToolAnnotations(title="Run Athena query (billed)", readOnlyHint=False,
                                      destructiveHint=False, openWorldHint=True))
def run_query(sql: str, estimated_scan_mb: float, purpose: str) -> dict:
    """Run a query that check_query allowed. `estimated_scan_mb` must be the value
    check_query returned; `purpose` is a one-line plain-English description shown to the approver."""
    s = settings()
    checked = _check(sql)
    if not checked["allowed"]:
        return checked
    server_mb = checked["estimated_scan_mb"]
    if abs(server_mb - estimated_scan_mb) > max(5.0, 0.1 * server_mb):
        return {"allowed": False, "stage": "estimate-mismatch",
                "reason": f"estimated_scan_mb={estimated_scan_mb} does not match the server estimate "
                          f"({server_mb} MB). Call check_query and pass its value."}
    try:
        qid = _athena().start_query_execution(
            QueryString=checked["sql"],
            QueryExecutionContext={"Database": s.database},
            WorkGroup=s.workgroup,
        )["QueryExecutionId"]
    except ClientError as e:
        return {"allowed": True, "state": "FAILED_TO_START", "error": e.response["Error"]["Message"]}
    _OWN_EXECUTIONS.add(qid)
    return _wait_and_fetch(qid, checked, deadline=time.monotonic() + s.query_timeout_s)


@mcp.tool(annotations=ToolAnnotations(title="Fetch query results", readOnlyHint=True, idempotentHint=True))
def get_results(execution_id: str) -> dict:
    """Results of a query run_query started that was still running when it returned."""
    if execution_id not in _OWN_EXECUTIONS:
        return {"error": "unknown execution id; only queries started by this server can be read"}
    return _wait_and_fetch(execution_id, {}, deadline=time.monotonic() + settings().query_timeout_s)


# --- Athena -----------------------------------------------------------------------

def _wait_and_fetch(qid: str, checked: dict, deadline: float) -> dict:
    s, athena = settings(), _athena()
    delay = 0.5
    while True:
        q = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = q["Status"]["State"]
        stats = q.get("Statistics", {})
        scanned = stats.get("DataScannedInBytes")
        if state not in ("QUEUED", "RUNNING"):
            break
        # The workgroup enforces BytesScannedCutoffPerQuery; this is a second stop
        # for workgroups created without one.
        if scanned and scanned > s.max_scan_bytes:
            athena.stop_query_execution(QueryExecutionId=qid)
            return {"execution_id": qid, "state": "CANCELLED", "error": "scan limit exceeded", "scanned_bytes": scanned}
        if time.monotonic() > deadline:
            return {"execution_id": qid, "state": state, "note": "still running; call get_results with this id"}
        time.sleep(delay)
        delay = min(delay * 1.5, 3.0)

    out = {
        "execution_id": qid,
        "state": state,
        "scanned_bytes": scanned,
        "scanned_mb": None if scanned is None else round(scanned / 1024**2, 2),
        "billed_usd": None if scanned is None else round(max(scanned, est.ATHENA_MIN_BYTES) / 1e12 * est.ATHENA_USD_PER_TB, 6),
        "engine_ms": stats.get("EngineExecutionTimeInMillis"),
    }
    if checked.get("estimated_scan_bytes") is not None:
        out["estimated_scan_bytes"] = checked["estimated_scan_bytes"]
    if state != "SUCCEEDED":
        out["error"] = q["Status"].get("StateChangeReason", "")
        return out

    columns, rows = [], []
    pages = athena.get_paginator("get_query_results").paginate(
        QueryExecutionId=qid, PaginationConfig={"MaxItems": s.max_rows + 1})
    for page in pages:
        if not columns:
            columns = [c["Name"] for c in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
        for r in page["ResultSet"]["Rows"]:
            values = [c.get("VarCharValue") for c in r["Data"]]
            if values == columns and not rows:
                continue  # header row
            rows.append(dict(zip(columns, values)))
    out.update(columns=columns, rows=rows[: s.max_rows], row_count=len(rows[: s.max_rows]),
               truncated=len(rows) > s.max_rows)
    return out


def serve():
    mcp.run("stdio")


if __name__ == "__main__":
    serve()
