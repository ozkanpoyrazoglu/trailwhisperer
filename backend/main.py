import functools
import hmac
import json
import os

import boto3
import sqlglot
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from pydantic import BaseModel, Field
from sqlglot import exp

REGION = os.getenv("AWS_REGION", "us-east-1")
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
GLUE_DATABASE = os.getenv("GLUE_DATABASE", "trailwhisperer_db")
GLUE_TABLE = os.getenv("GLUE_TABLE", "cloudtrail_logs")
GLUE_VPC_TABLE = os.getenv("GLUE_VPC_TABLE", "vpc_flow_logs")
ATHENA_WORKGROUP = os.getenv("ATHENA_WORKGROUP", "primary")
# Optional. Deployed workgroups enforce their own OutputLocation, but local dev
# against the `primary` workgroup has none — set this to write results to S3.
ATHENA_OUTPUT_LOCATION = os.getenv("ATHENA_OUTPUT_LOCATION")
MAX_DAYS = int(os.getenv("ALLOWED_TIME_RANGE_MAX_DAYS", "90"))
MAX_ROWS = 1000
SUMMARY_ROWS = 200

app = FastAPI(title="TrailWhisperer Orchestrator")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


@functools.lru_cache(maxsize=1)
def _bedrock():
    return boto3.client("bedrock-runtime", region_name=REGION)


@functools.lru_cache(maxsize=1)
def _athena():
    return boto3.client("athena", region_name=REGION)


@functools.lru_cache(maxsize=1)
def auth_token():
    token = os.getenv("AUTH_TOKEN")
    if token:
        return token
    arn = os.getenv("AUTH_SECRET_ARN")
    if arn:
        sm = boto3.client("secretsmanager", region_name=REGION)
        raw = sm.get_secret_value(SecretId=arn)["SecretString"]
        try:
            return json.loads(raw)["token"]
        except (ValueError, KeyError):
            return raw
    return None


def require_auth(authorization: str = Header(default="")):
    expected = auth_token()
    if not expected:
        raise HTTPException(500, "auth token not configured")
    presented = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(401, "invalid or missing token")


# --- Grounding -------------------------------------------------------------

CRIB = (
    "eventtime: ISO8601 UTC timestamp of the API call. "
    "eventname/eventsource: the API action and service. "
    "useridentity: struct(type, arn, username, accountid, sessioncontext...). "
    "sourceipaddress, useragent: caller origin. "
    "errorcode/errormessage: set when the call failed/was denied. "
    "requestparameters/responseelements: JSON strings (not structs). "
    "To read a TOP-LEVEL field, use json_extract_scalar(requestparameters, '$.groupId'). "
    "Nested arrays (e.g. security-group ipPermissions -> ipRanges) are awkward to unnest reliably, "
    "so for values buried inside arrays prefer RESILIENT string matching on the raw JSON, e.g. an "
    "open CIDR + port 22 rule: requestparameters LIKE '%\"cidrIp\":\"0.0.0.0/0\"%' "
    "AND requestparameters LIKE '%\"fromPort\":22%' (note: AWS may serialize with or without a space "
    "after the colon, so match the bare token like '%\"fromPort\":22%' or use '%fromPort%22%'). "
    "awsregion, recipientaccountid. "
    "Partitions: account, region, dt. "
    "dt is a STRING partition key formatted 'yyyy/MM/dd' (e.g. '2026/07/18'); "
    "it is MANDATORY in WHERE for partition pruning and must be filtered as "
    "dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')."
)

VPC_CRIB = (
    "version, account_id, interface_id: flow metadata. "
    "srcaddr/dstaddr: source/destination IP. srcport/dstport: ports. "
    "protocol: IANA protocol number (6=TCP, 17=UDP, 1=ICMP). "
    "packets, bytes: volume transferred. "
    "start, end: Unix epoch SECONDS of the flow window "
    "(`end` is a reserved word — always quote it as \"end\"). "
    "action: 'ACCEPT' or 'REJECT'. log_status: 'OK'/'NODATA'/'SKIPDATA'. "
    "Partitions: account, region, dt. "
    "dt is a STRING partition key formatted 'yyyy/MM/dd' (e.g. '2026/07/18'); "
    "it is MANDATORY in WHERE for partition pruning and must be filtered as "
    "dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')."
)

FEWSHOT = (
    "Q: Who changed a security group last week?\n"
    f"SQL: SELECT eventtime, useridentity.arn, eventname, sourceipaddress FROM {GLUE_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
    "AND eventname IN ('AuthorizeSecurityGroupIngress','RevokeSecurityGroupIngress','AuthorizeSecurityGroupEgress') "
    "AND eventtime >= to_iso8601(current_timestamp - interval '7' day) ORDER BY eventtime DESC;\n\n"
    "Q: Failed console logins in the last 3 days?\n"
    f"SQL: SELECT eventtime, useridentity.username, sourceipaddress, errormessage FROM {GLUE_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '3' day, '%Y/%m/%d') "
    "AND eventname = 'ConsoleLogin' AND errorcode IS NOT NULL "
    "AND eventtime >= to_iso8601(current_timestamp - interval '3' day) ORDER BY eventtime DESC;\n\n"
    "Q: Which hosts had rejected connections on port 22 yesterday?\n"
    f'SQL: SELECT from_unixtime("start") AS flow_start, srcaddr, dstaddr, dstport, action FROM {GLUE_VPC_TABLE} '
    "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
    "AND action = 'REJECT' AND dstport = 22 "
    "AND \"start\" >= to_unixtime(current_timestamp - interval '1' day) ORDER BY \"start\" DESC;\n\n"
    "Q: Did IP 198.51.100.42 make any API calls or network connections yesterday?\n"
    "SQL: SELECT from_iso8601_timestamp(eventtime) AS event_time, 'cloudtrail' AS source, eventname AS action, useridentity.arn AS identity "
    f"FROM {GLUE_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
    "AND sourceipaddress = '198.51.100.42' "
    "AND eventtime >= to_iso8601(current_timestamp - interval '1' day) "
    "UNION ALL "
    "SELECT from_unixtime(\"start\") AS event_time, 'vpc_flow' AS source, "
    "action AS action, srcaddr AS identity "
    f"FROM {GLUE_VPC_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
    "AND srcaddr = '198.51.100.42' "
    "AND \"start\" >= to_unixtime(current_timestamp - interval '1' day) "
    "ORDER BY event_time DESC;\n\n"
    "Q: Who opened SSH or RDP to the public (0.0.0.0/0) this week?\n"
    "SQL: SELECT eventtime, useridentity.arn, eventname, "
    "json_extract_scalar(requestparameters, '$.groupId') AS group_id, sourceipaddress "
    f"FROM {GLUE_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
    "AND eventname IN ('AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress') "
    "AND requestparameters LIKE '%\"cidrIp\":\"0.0.0.0/0\"%' "
    "AND (requestparameters LIKE '%\"fromPort\":22%' OR requestparameters LIKE '%\"fromPort\":3389%') "
    "AND eventtime >= to_iso8601(current_timestamp - interval '7' day) ORDER BY eventtime DESC;"
)

SQL_SYSTEM = (
    "You translate natural-language audit questions into a single Amazon Athena (Trino SQL) query.\n"
    "Pick exactly ONE whitelisted table for the question:\n"
    f"- `{GLUE_TABLE}` — AWS API/management activity (who did what) from CloudTrail.\n"
    f"- `{GLUE_VPC_TABLE}` — network traffic (connections, IPs, ports, accepted/rejected flows) from VPC Flow Logs.\n"
    "RULES:\n"
    "- Output ONLY the SQL, no prose, no markdown fences.\n"
    "- Exactly one read-only SELECT. Never INSERT/UPDATE/DELETE/CREATE/DROP/ALTER/UNLOAD.\n"
    f"- Query only the whitelisted tables (`{GLUE_TABLE}` and/or `{GLUE_VPC_TABLE}`); never any other table.\n"
    "- CROSS-LOG CORRELATION: when a question spans BOTH what someone did (API activity) AND their "
    f"network traffic — e.g. investigating a single IP address across `{GLUE_TABLE}` and `{GLUE_VPC_TABLE}` "
    "— correlate them with a `UNION ALL` of two SELECT branches (one per table). Do NOT join the tables. "
    "Both branches MUST project the SAME column count with matching types and aliases, e.g. "
    "(event_time, source, action, identity), casting/normalizing as needed so the shapes line up. "
    "CRITICALLY, BOTH branches MUST independently enforce the mandatory `dt` partition filter AND their "
    "own event-timestamp predicate (CloudTrail uses `eventtime`, VPC uses \"start\").\n"
    "- MANDATORY PARTITION PRUNING: EVERY query MUST filter the `dt` partition key in WHERE, "
    "using exactly this form (N = number of days in the window):\n"
    "      dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')\n"
    "  `dt` is a STRING partition formatted 'yyyy/MM/dd'. A query WITHOUT a `dt` filter is REJECTED — "
    "never emit one. This applies to BOTH tables.\n"
    "- ALSO include a precise time-window predicate on the event's own timestamp. If the user gives no "
    f"range, default to the last {MAX_DAYS} days and never exceed it. Use the SAME N for `dt` and the "
    "timestamp column:\n"
    "    * CloudTrail: filter `eventtime` (ISO8601 string) with to_iso8601(current_timestamp - interval 'N' day).\n"
    "    * VPC Flow Logs: filter \"start\" (Unix epoch seconds, quote the reserved word \"end\" too) "
    "with to_unixtime(current_timestamp - interval 'N' day).\n"
    "- Prefer explicit columns, ORDER BY the time column DESC, and add a LIMIT when reasonable.\n\n"
    f"CLOUDTRAIL (`{GLUE_TABLE}`) COLUMNS:\n{CRIB}\n\n"
    f"VPC FLOW LOGS (`{GLUE_VPC_TABLE}`) COLUMNS:\n{VPC_CRIB}\n\n"
    f"EXAMPLES:\n{FEWSHOT}"
)

SUMMARY_SYSTEM = (
    "You are a cloud security analyst. Summarize ONLY the log rows provided (JSON; "
    "CloudTrail API activity or VPC Flow Logs network traffic). "
    "Do not invent data not present in the rows. Return STRICT JSON: "
    '{"summary": "<2-4 sentence narrative answering the question>", '
    '"flags": ["<notable/anomalous observation>", ...]}. '
    "Flags are heuristic: repeated failures, unusual principals/IPs, privilege changes, "
    "sensitive API calls, off-hours activity. Empty list if nothing stands out."
)

# Plain-language rendering of the generated SQL, so a non-technical approver can
# understand what they are authorizing before it runs (human-in-the-loop).
EXPLAIN_SYSTEM = (
    "You explain an Athena SQL query to a NON-TECHNICAL auditor who does not read SQL. "
    "Given their question and the query, write 1-2 short plain-English sentences describing "
    "what the query looks for and the time window it covers. "
    "No SQL keywords, no table or column names, no markdown, no code — just a clear explanation."
)


class GenerateRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    model_id: str | None = None


class ExecuteRequest(BaseModel):
    sql: str = Field(min_length=8)


def _invoke(system: str, user: str, max_tokens: int = 1024, model_id: str | None = None) -> str:
    # Converse gives a single schema across all Bedrock chat models
    # (Claude, Amazon Nova, Qwen, Llama, Mistral, DeepSeek, ...), so the same
    # code works whichever model the user selects.
    try:
        resp = _bedrock().converse(
            modelId=model_id or MODEL_ID,
            system=[{"text": system}],
            messages=[{"role": "user", "content": [{"text": user}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
        )
    except ClientError as e:
        raise HTTPException(502, f"bedrock error: {e.response['Error'].get('Message', str(e))}")
    blocks = resp["output"]["message"]["content"]
    # Reasoning models (Qwen thinking, DeepSeek-R1) emit a reasoning block first,
    # then the answer — take the first text block.
    return next((b["text"] for b in blocks if "text" in b), "").strip()


def _clean_sql(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1] if "```" in t[3:] else t[3:]
        if t.lower().startswith("sql"):
            t = t[3:]
    return t.strip().rstrip(";").strip()


# --- Guardrail helpers -----------------------------------------------------
# A `dt` predicate that actually prunes partitions must narrow the scan: a lower
# bound (>=/>), an exact match (=/IN), or a range (BETWEEN). Upper-bound-only
# (</<=), IS [NOT] NULL, LIKE and <> do NOT bound how far back Athena scans, so
# they don't count as binding.
_DT_BINDING = (exp.GTE, exp.GT, exp.EQ, exp.Between, exp.In)
_UNIT_DAYS = {
    "day": 1, "days": 1, "week": 7, "weeks": 7,
    "month": 30, "months": 30, "year": 365, "years": 365,
}


def _own_tables(select: exp.Select) -> set[str]:
    """Whitelisted table names in THIS select's own FROM/joins (not nested
    subqueries — those belong to their own inner select)."""
    return {
        t.name.lower()
        for t in select.find_all(exp.Table)
        if t.name and t.find_ancestor(exp.Select) is select
    }


def _under_or(node: exp.Expression, where: exp.Where) -> bool:
    """True if `node` sits under an OR anywhere between it and its WHERE — such a
    predicate can't be relied on to prune (Athena won't prune across an OR)."""
    p = node.parent
    while p is not None and p is not where:
        if isinstance(p, exp.Or):
            return True
        p = p.parent
    return False


def _has_binding_dt(select: exp.Select) -> bool:
    """True if this select's own WHERE contains a binding `dt` predicate in AND
    context (not under OR, not only inside a nested subquery)."""
    where = select.args.get("where")
    if not where:
        return False
    for cmp in where.find_all(*_DT_BINDING):
        # the comparison must belong to THIS select's WHERE, not a nested subquery
        if cmp.find_ancestor(exp.Select) is not select:
            continue
        if _under_or(cmp, where):
            continue
        # the `dt` operand must itself belong to this select (guards against a
        # dt filter that lives only inside a subquery on the RHS, e.g. IN (...))
        if any(c.name.lower() == "dt" and c.find_ancestor(exp.Select) is select
               for c in cmp.find_all(exp.Column)):
            return True
    return False


def _window_within_cap(stmt: exp.Expression) -> bool:
    """Reject `interval 'N' <unit>` windows longer than MAX_DAYS."""
    for iv in stmt.find_all(exp.Interval):
        unit_node = iv.args.get("unit")
        unit = (unit_node.name.lower() if unit_node else "")
        factor = _UNIT_DAYS.get(unit)
        if factor is None:  # sub-day units (hour/minute/...) never exceed the cap
            continue
        try:
            n = int(iv.this.name)
        except (AttributeError, ValueError):
            continue
        if n * factor > MAX_DAYS:
            return False
    return True


def validate_sql(sql: str):
    """Parse-based guardrail. Returns (ok, reason)."""
    try:
        statements = [s for s in sqlglot.parse(sql, dialect="trino") if s]
    except Exception as e:
        return False, f"could not parse SQL: {e}"
    if len(statements) != 1:
        return False, "exactly one statement is allowed"
    stmt = statements[0]
    forbidden = (
        exp.Insert, exp.Update, exp.Delete, exp.Create, exp.Drop,
        exp.Alter, exp.Merge, exp.Command,
    )
    if any(stmt.find(f) for f in forbidden):
        return False, "only read-only SELECT statements are allowed"
    if not isinstance(stmt, (exp.Select, exp.Union)):
        return False, "query must be a SELECT"
    allowed = {GLUE_TABLE.lower(), GLUE_VPC_TABLE.lower()}
    tables = {t.name.lower() for t in stmt.find_all(exp.Table) if t.name}
    if tables - allowed:
        return False, f"only tables `{GLUE_TABLE}` or `{GLUE_VPC_TABLE}` may be queried"
    wheres = list(stmt.find_all(exp.Where))
    if not wheres:
        return False, "a time-window filter is required"

    # Partition pruning is non-negotiable: EVERY select that scans a whitelisted
    # table must itself bind the `dt` partition key (yyyy/MM/dd, shared by both
    # tables). Checking mere presence of the column name is not enough — it lets
    # OR branches, non-range predicates (IS NOT NULL/LIKE), subquery-only filters
    # and unpruned UNION branches through. We require a binding predicate in the
    # AND context of each scanning select's own WHERE.
    scanning = [s for s in stmt.find_all(exp.Select) if _own_tables(s) & allowed]
    if not scanning:
        return False, "query must scan a whitelisted table"
    for s in scanning:
        if not _has_binding_dt(s):
            return False, (
                "WHERE must bind the `dt` partition key with a range/equality filter "
                "in AND context (not under OR, not only in a subquery), e.g. "
                "dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')"
            )

    # Enforce the configured maximum time window (partition pruning alone doesn't
    # cap how far back the window reaches).
    if not _window_within_cap(stmt):
        return False, f"time window exceeds the {MAX_DAYS}-day maximum"

    return True, None


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "model": MODEL_ID,
        "tables": [f"{GLUE_DATABASE}.{GLUE_TABLE}", f"{GLUE_DATABASE}.{GLUE_VPC_TABLE}"],
    }


@app.post("/api/generate-sql", dependencies=[Depends(require_auth)])
def generate_sql(req: GenerateRequest):
    sql = _clean_sql(_invoke(SQL_SYSTEM, req.question, model_id=req.model_id))
    ok, reason = validate_sql(sql)
    if not ok:
        # one self-correction round
        sql = _clean_sql(
            _invoke(SQL_SYSTEM, f"{req.question}\n\nYour previous SQL was rejected: {reason}\nSQL was:\n{sql}\nFix it.", model_id=req.model_id)
        )
        ok, reason = validate_sql(sql)
    if not ok:
        raise HTTPException(422, f"could not produce a safe query: {reason}")
    # Best-effort plain-language explanation; never fail generation if it errors.
    explanation = ""
    try:
        explanation = _invoke(
            EXPLAIN_SYSTEM, f"Question: {req.question}\n\nSQL:\n{sql}", max_tokens=256, model_id=req.model_id
        )
    except HTTPException:
        explanation = ""
    return {"sql": sql, "explanation": explanation}


@app.post("/api/execute-sql", dependencies=[Depends(require_auth)])
def execute_sql(req: ExecuteRequest):
    sql = req.sql.strip().rstrip(";").strip()
    ok, reason = validate_sql(sql)
    if not ok:
        raise HTTPException(422, f"rejected by guardrail: {reason}")
    params = {
        "QueryString": sql,
        "QueryExecutionContext": {"Database": GLUE_DATABASE},
        "WorkGroup": ATHENA_WORKGROUP,
    }
    if ATHENA_OUTPUT_LOCATION:
        params["ResultConfiguration"] = {"OutputLocation": ATHENA_OUTPUT_LOCATION}
    try:
        resp = _athena().start_query_execution(**params)
    except ClientError as e:
        raise HTTPException(502, f"athena error: {e.response['Error'].get('Message', str(e))}")
    return {"execution_id": resp["QueryExecutionId"]}


def _fetch_rows(execution_id: str):
    paginator = _athena().get_paginator("get_query_results")
    header = None
    rows = []
    for page in paginator.paginate(
        QueryExecutionId=execution_id, PaginationConfig={"MaxItems": MAX_ROWS + 1}
    ):
        for r in page["ResultSet"]["Rows"]:
            values = [c.get("VarCharValue") for c in r["Data"]]
            if header is None:
                header = values
            else:
                rows.append(dict(zip(header, values)))
    return header or [], rows


def _parse_summary_json(text: str):
    """Extract the {summary, flags} object even if the model wraps it in
    markdown fences or surrounding prose. Returns dict or None."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    # Fall back to the outermost {...} span (handles ```json fences / prose).
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except ValueError:
            return None
    return None


def _summarize(question: str, rows: list, model_id: str | None = None):
    sample = rows[:SUMMARY_ROWS]
    user = f"Question: {question or 'Summarize this CloudTrail activity.'}\n\nRows (JSON):\n{json.dumps(sample, default=str)}"
    text = _invoke(SUMMARY_SYSTEM, user, max_tokens=800, model_id=model_id)
    data = _parse_summary_json(text)
    if isinstance(data, dict):
        return data.get("summary", ""), data.get("flags", [])
    return text, []


@app.get("/api/results/{execution_id}", dependencies=[Depends(require_auth)])
def get_results(execution_id: str = Path(min_length=8), question: str = "", model_id: str = ""):
    try:
        info = _athena().get_query_execution(QueryExecutionId=execution_id)["QueryExecution"]
    except ClientError as e:
        raise HTTPException(502, f"athena error: {e.response['Error'].get('Message', str(e))}")

    state = info["Status"]["State"]
    scanned = info.get("Statistics", {}).get("DataScannedInBytes")

    if state in ("QUEUED", "RUNNING"):
        return {"status": "running", "state": state}
    if state in ("FAILED", "CANCELLED"):
        reason = info["Status"].get("StateChangeReason", "query did not succeed")
        return {"status": "failed", "state": state, "error": reason, "bytes_scanned": scanned}

    columns, rows = _fetch_rows(execution_id)
    summary, flags = _summarize(question, rows, model_id or None) if rows else ("No matching events were found.", [])
    return {
        "status": "succeeded",
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "truncated": len(rows) >= MAX_ROWS,
        "bytes_scanned": scanned,
        "summary": summary,
        "flags": flags,
    }


handler = Mangum(app)
