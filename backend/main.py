import functools
import hmac
import json
import os
import time

import boto3
import sqlglot
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from pydantic import BaseModel, Field
from sqlglot import exp

REGION = os.getenv("AWS_REGION", "us-east-1")
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "global.anthropic.claude-sonnet-4-6")
GLUE_DATABASE = os.getenv("GLUE_DATABASE", "trailwhisperer_db")
GLUE_TABLE = os.getenv("GLUE_TABLE", "cloudtrail_logs")
GLUE_VPC_TABLE = os.getenv("GLUE_VPC_TABLE", "vpc_flow_logs")
# Optional Prowler findings table (only set when EnableProwlerScan=true in CFN).
# When present, the model may query it and correlate the static security posture
# with the time-series logs. Prowler findings are a point-in-time snapshot, so this
# table is NOT time-partitioned and is exempt from the mandatory `dt` filter.
GLUE_PROWLER_TABLE = os.getenv("GLUE_PROWLER_TABLE")
ATHENA_WORKGROUP = os.getenv("ATHENA_WORKGROUP", "primary")
# Optional. Deployed workgroups enforce their own OutputLocation, but local dev
# against the `primary` workgroup has none — set this to write results to S3.
ATHENA_OUTPUT_LOCATION = os.getenv("ATHENA_OUTPUT_LOCATION")
MAX_DAYS = int(os.getenv("ALLOWED_TIME_RANGE_MAX_DAYS", "90"))
MAX_ROWS = 1000
SUMMARY_ROWS = 200
# Conversational memory (DynamoDB). Optional: unset locally → memory disabled.
SESSION_TABLE = os.getenv("DYNAMODB_SESSION_TABLE")
HISTORY_TTL_SECONDS = 24 * 3600  # sessions self-expire after 24h (DynamoDB TTL)

app = FastAPI(title="TrailWhisperer Orchestrator")
# ALLOWED_ORIGIN is the deployed SPA (CloudFront) origin, injected by CloudFormation.
# Unset/empty (local dev) falls back to "*" so docker compose keeps working.
_allowed_origin = os.getenv("ALLOWED_ORIGIN")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[_allowed_origin] if _allowed_origin else ["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@functools.lru_cache(maxsize=1)
def _bedrock():
    return boto3.client("bedrock-runtime", region_name=REGION)


@functools.lru_cache(maxsize=1)
def _athena():
    return boto3.client("athena", region_name=REGION)


@functools.lru_cache(maxsize=1)
def _sessions_table():
    return boto3.resource("dynamodb", region_name=REGION).Table(SESSION_TABLE)


# --- Conversational memory (best-effort; never breaks a request) -----------

def history_get(session_id: str | None) -> list[dict]:
    """Prior turns for a session as [{role, content}], oldest first."""
    if not (session_id and SESSION_TABLE):
        return []
    try:
        item = _sessions_table().get_item(Key={"session_id": session_id}).get("Item")
    except ClientError:
        return []
    return (item or {}).get("messages", [])


def history_append(session_id: str | None, role: str, text: str):
    """Append one turn to a session with a refreshed 24h TTL."""
    if not (session_id and SESSION_TABLE and text):
        return
    msg = {"role": role, "content": text[:8000]}
    try:
        _sessions_table().update_item(
            Key={"session_id": session_id},
            UpdateExpression=(
                "SET messages = list_append(if_not_exists(messages, :empty), :m), "
                "#ttl = :ttl"
            ),
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":empty": [], ":m": [msg],
                ":ttl": int(time.time()) + HISTORY_TTL_SECONDS,
            },
        )
    except ClientError:
        pass  # memory is a convenience, not a hard dependency


def to_converse_messages(history: list[dict]) -> list[dict]:
    """Turn stored {role, content} turns into Bedrock Converse messages.
    Merges consecutive same-role turns (a query whose results were never stored
    leaves a dangling user turn) so the required user/assistant alternation — and
    a leading user turn — always holds."""
    msgs: list[dict] = []
    for m in history:
        role, text = m.get("role"), m.get("content")
        if role not in ("user", "assistant") or not text:
            continue
        if msgs and msgs[-1]["role"] == role:
            msgs[-1]["content"].append({"text": text})
        else:
            msgs.append({"role": role, "content": [{"text": text}]})
    while msgs and msgs[0]["role"] != "user":
        msgs.pop(0)
    return msgs


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

PROWLER_CRIB = (
    "Prowler is an AWS security scanner; each row is ONE check result (a point-in-time "
    "posture snapshot, NOT time-series). "
    "status: 'PASS' or 'FAIL' (a FAIL is an open security issue). "
    "severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'. "
    "check_id: the Prowler check identifier, e.g. "
    "'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22' (SSH open to the internet) "
    "or '..._to_tcp_port_3389' (RDP). Match with `=` or `LIKE`. "
    "check_title: human-readable check description. status_extended: one-line detail of the result. "
    "service_name: the AWS service (e.g. 'ec2', 's3', 'iam'). region: AWS region of the resource. "
    "resource_id: the flagged resource (e.g. a security-group id like 'sg-0abc123'); "
    "resource_arn: its full ARN. account_id: the audited account. "
    "IMPORTANT: this table is NOT partitioned and has NO time column — do NOT add a `dt` or "
    "event-time filter when querying it alone; filter by status/severity/check_id/service instead."
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

# Prowler few-shot (appended to FEWSHOT only when GLUE_PROWLER_TABLE is set).
# Demonstrates a plain findings query and cross-log correlation: take an open
# security-group finding and check VPC Flow Logs for actual internet traffic.
PROWLER_FEWSHOT = (
    "\n\nQ: List my critical Prowler findings.\n"
    f"SQL: SELECT check_id, check_title, severity, service_name, resource_id, region "
    f"FROM {GLUE_PROWLER_TABLE} "
    "WHERE status = 'FAIL' AND severity = 'critical' ORDER BY service_name;\n\n"
    "Q: Did the open security groups flagged by Prowler receive any internet traffic?\n"
    "SQL: SELECT 'prowler_finding' AS source, check_id AS detail, resource_id AS resource, severity AS extra "
    f"FROM {GLUE_PROWLER_TABLE} "
    "WHERE status = 'FAIL' "
    "AND check_id LIKE 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_%' "
    "UNION ALL "
    "SELECT 'vpc_flow' AS source, action AS detail, dstaddr AS resource, CAST(dstport AS varchar) AS extra "
    f"FROM {GLUE_VPC_TABLE} "
    "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
    "AND action = 'ACCEPT' AND dstport IN (22, 3389) "
    "AND \"start\" >= to_unixtime(current_timestamp - interval '7' day);"
)

# Conditional Prowler grounding — only advertised when the findings table exists.
_PROWLER_TABLE_LINE = (
    f"- `{GLUE_PROWLER_TABLE}` — Prowler security-scan findings: static security posture "
    "(which checks PASSed/FAILed, severity, flagged resource ids/arns). NOT time-series — do "
    "NOT add a `dt`/time filter when querying it alone.\n"
    if GLUE_PROWLER_TABLE else ""
)
_WHITELIST = f"`{GLUE_TABLE}` and/or `{GLUE_VPC_TABLE}`" + (
    f" and/or `{GLUE_PROWLER_TABLE}`" if GLUE_PROWLER_TABLE else ""
)
_PROWLER_CORRELATION = (
    "- PROWLER CORRELATION: to check whether a static Prowler finding is actually being exploited, "
    f"`UNION ALL` a `{GLUE_PROWLER_TABLE}` branch (the finding: check_id/status='FAIL'/resource_id) "
    f"with a `{GLUE_VPC_TABLE}` (or `{GLUE_TABLE}`) branch (the live traffic/activity). Align the "
    "projected columns across branches. The Prowler branch has NO time/`dt` filter (it is a snapshot); "
    "the log branch(es) STILL enforce their mandatory `dt` + event-timestamp predicates.\n"
    if GLUE_PROWLER_TABLE else ""
)
_PROWLER_SCHEMA = (
    f"\n\nPROWLER FINDINGS (`{GLUE_PROWLER_TABLE}`) COLUMNS:\n{PROWLER_CRIB}"
    if GLUE_PROWLER_TABLE else ""
)
_PROWLER_EXAMPLES = PROWLER_FEWSHOT if GLUE_PROWLER_TABLE else ""
_PROWLER_EXEMPT = (
    " (The Prowler findings table is exempt: it is a static snapshot with no `dt`.)"
    if GLUE_PROWLER_TABLE else ""
)

SQL_SYSTEM = (
    "You are a cloud security analyst assistant investigating AWS CloudTrail and VPC Flow "
    "Logs with an auditor. You can see the earlier turns of this conversation.\n"
    "Choose ONE of two responses each turn:\n"
    "1) ANSWER FROM MEMORY: if the question can be answered from the conversation so far "
    "(a follow-up about data already returned, a clarification, or a general question), reply "
    "directly in plain text. Do NOT call any tool and do NOT invent data you were not given.\n"
    "2) QUERY THE LOGS: if answering needs NEW data from the logs, call the `query_athena` tool "
    "with a single Athena (Trino SQL) SELECT following ALL rules below. Put the SQL ONLY in the "
    "tool's `sql` argument — never in your text reply.\n"
    "When you query, pick the whitelisted table(s) that fit the question:\n"
    f"- `{GLUE_TABLE}` — AWS API/management activity (who did what) from CloudTrail.\n"
    f"- `{GLUE_VPC_TABLE}` — network traffic (connections, IPs, ports, accepted/rejected flows) from VPC Flow Logs.\n"
    f"{_PROWLER_TABLE_LINE}"
    "SQL RULES (for the `query_athena` `sql` argument):\n"
    "- The `sql` argument holds ONLY the SQL — no prose, no markdown fences.\n"
    "- Exactly one read-only SELECT. Never INSERT/UPDATE/DELETE/CREATE/DROP/ALTER/UNLOAD.\n"
    f"- Query only the whitelisted tables ({_WHITELIST}); never any other table.\n"
    "- CROSS-LOG CORRELATION: when a question spans BOTH what someone did (API activity) AND their "
    f"network traffic — e.g. investigating a single IP address across `{GLUE_TABLE}` and `{GLUE_VPC_TABLE}` "
    "— correlate them with a `UNION ALL` of two SELECT branches (one per table). Do NOT join the tables. "
    "Both branches MUST project the SAME column count with matching types and aliases, e.g. "
    "(event_time, source, action, identity), casting/normalizing as needed so the shapes line up. "
    "CRITICALLY, each LOG branch MUST independently enforce the mandatory `dt` partition filter AND its "
    "own event-timestamp predicate (CloudTrail uses `eventtime`, VPC uses \"start\").\n"
    f"{_PROWLER_CORRELATION}"
    "- MANDATORY PARTITION PRUNING: EVERY query against a LOG table (CloudTrail / VPC Flow Logs) MUST "
    "filter the `dt` partition key in WHERE, using exactly this form (N = number of days in the window):\n"
    "      dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')\n"
    "  `dt` is a STRING partition formatted 'yyyy/MM/dd'. A LOG query WITHOUT a `dt` filter is REJECTED — "
    f"never emit one.{_PROWLER_EXEMPT}\n"
    "- ALSO include a precise time-window predicate on the event's own timestamp. If the user gives no "
    f"range, default to the last {MAX_DAYS} days and never exceed it. Use the SAME N for `dt` and the "
    "timestamp column:\n"
    "    * CloudTrail: filter `eventtime` (ISO8601 string) with to_iso8601(current_timestamp - interval 'N' day).\n"
    "    * VPC Flow Logs: filter \"start\" (Unix epoch seconds, quote the reserved word \"end\" too) "
    "with to_unixtime(current_timestamp - interval 'N' day).\n"
    "- Prefer explicit columns, ORDER BY the time column DESC, and add a LIMIT when reasonable.\n"
    "- QUOTING (critical): delimit EVERY string literal with SINGLE quotes only. NEVER use a double "
    "quote to open or close a literal. When matching JSON in `requestparameters`, the double-quote "
    "characters are part of the JSON payload and belong INSIDE a single-quoted pattern — the pattern "
    "must both open and close with a single quote, e.g. requestparameters LIKE '%\"groupId\":%'. A "
    "pattern like '%\"groupId\":%\" is malformed and will be rejected.\n\n"
    f"CLOUDTRAIL (`{GLUE_TABLE}`) COLUMNS:\n{CRIB}\n\n"
    f"VPC FLOW LOGS (`{GLUE_VPC_TABLE}`) COLUMNS:\n{VPC_CRIB}"
    f"{_PROWLER_SCHEMA}\n\n"
    f"EXAMPLES:\n{FEWSHOT}{_PROWLER_EXAMPLES}"
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


# Bedrock Tool Use: the model calls this to fetch NEW data; otherwise it answers
# in plain text from conversation memory. We never auto-run the returned SQL —
# it still goes through the guardrail + human approval (constraint #2).
QUERY_TOOL = {
    "tools": [{
        "toolSpec": {
            "name": "query_athena",
            "description": (
                "Run a read-only Athena SQL query against the CloudTrail / VPC Flow Logs "
                "tables to fetch NEW data needed to answer the question. Only call this when "
                "the answer requires querying the logs; if the conversation already contains "
                "the answer, reply in plain text instead of calling this tool."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "A single read-only Trino SELECT that follows every stated rule (mandatory dt partition filter, time-window predicate, whitelisted tables only).",
                    }
                },
                "required": ["sql"],
            }},
        }
    }]
}


class GenerateRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    model_id: str | None = None
    session_id: str | None = Field(default=None, max_length=128)


class ExecuteRequest(BaseModel):
    sql: str = Field(min_length=8)


def _converse(system: str, messages: list[dict], tool_config: dict | None = None,
              max_tokens: int = 1024, model_id: str | None = None) -> dict:
    # Converse gives a single schema across all Bedrock chat models
    # (Claude, Amazon Nova, Qwen, Llama, Mistral, DeepSeek, ...), so the same
    # code works whichever model the user selects.
    kwargs = dict(
        modelId=model_id or MODEL_ID,
        system=[{"text": system}],
        messages=messages,
        inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
    )
    if tool_config:
        kwargs["toolConfig"] = tool_config
    try:
        return _bedrock().converse(**kwargs)
    except ClientError as e:
        raise HTTPException(502, f"bedrock error: {e.response['Error'].get('Message', str(e))}")


def _invoke(system: str, user: str, max_tokens: int = 1024, model_id: str | None = None) -> str:
    resp = _converse(system, [{"role": "user", "content": [{"text": user}]}],
                     max_tokens=max_tokens, model_id=model_id)
    blocks = resp["output"]["message"]["content"]
    # Reasoning models (Qwen thinking, DeepSeek-R1) emit a reasoning block first,
    # then the answer — take the first text block.
    return next((b["text"] for b in blocks if "text" in b), "").strip()


def _tool_input(resp: dict, name: str) -> dict | None:
    """The tool-call input if the model invoked `name`, else None."""
    for b in resp["output"]["message"]["content"]:
        if b.get("toolUse", {}).get("name") == name:
            return b["toolUse"].get("input", {})
    return None


def _text_of(resp: dict) -> str:
    return next((b["text"] for b in resp["output"]["message"]["content"] if "text" in b), "").strip()


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
    # Time-partitioned LOG tables require the mandatory `dt` filter; the optional
    # Prowler findings table is a static snapshot (no partitions), so it is
    # whitelisted for scanning but exempt from the `dt` requirement.
    time_partitioned = {GLUE_TABLE.lower(), GLUE_VPC_TABLE.lower()}
    allowed = set(time_partitioned)
    if GLUE_PROWLER_TABLE:
        allowed.add(GLUE_PROWLER_TABLE.lower())
    tables = {t.name.lower() for t in stmt.find_all(exp.Table) if t.name}
    if not tables:
        return False, "query must scan a whitelisted table"
    if tables - allowed:
        allowed_list = "`, `".join(sorted(allowed))
        return False, f"only tables `{allowed_list}` may be queried"

    # Partition pruning is non-negotiable for the LOG tables: EVERY select that
    # scans a time-partitioned table must itself bind the `dt` partition key
    # (yyyy/MM/dd). Checking mere presence of the column name is not enough — it
    # lets OR branches, non-range predicates (IS NOT NULL/LIKE), subquery-only
    # filters and unpruned UNION branches through. We require a binding predicate
    # in the AND context of each scanning select's own WHERE. Prowler-only selects
    # are skipped (no partitions / no time column).
    scanning = [s for s in stmt.find_all(exp.Select) if _own_tables(s) & time_partitioned]
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
    # Intentionally minimal: a bare liveness probe that discloses nothing pre-auth.
    return {"status": "ok"}


@app.post("/api/generate-sql", dependencies=[Depends(require_auth)])
def generate_sql(req: GenerateRequest):
    # Agentic routing: give the model the conversation so far + the query_athena
    # tool. It either answers from memory (plain text) or calls the tool with SQL.
    convo = history_get(req.session_id) + [{"role": "user", "content": req.question}]
    resp = _converse(SQL_SYSTEM, to_converse_messages(convo),
                     tool_config=QUERY_TOOL, model_id=req.model_id)
    tool = _tool_input(resp, "query_athena")

    if tool is None:
        # No query needed — the model answered directly. Persist the exchange so
        # later turns keep the context, and return it for immediate display.
        answer = _text_of(resp) or "I don't have enough information to answer that yet."
        history_append(req.session_id, "user", req.question)
        history_append(req.session_id, "assistant", answer)
        return {"chat_response": answer, "session_id": req.session_id}

    sql = _clean_sql(tool.get("sql", ""))
    ok, reason = validate_sql(sql)
    # Up to two self-correction rounds: feed the rejection reason + bad SQL back to
    # the model. Smaller models (e.g. Nova) often mangle string-literal quoting and
    # need more than one shot to recover. Re-issue as a fresh turn (proposed SQL +
    # correction request) to preserve user/assistant alternation.
    for _ in range(2):
        if ok:
            break
        convo = convo + [
            {"role": "assistant", "content": f"(proposed query) {sql}"},
            {"role": "user", "content": (
                f"That query was rejected by the guardrail: {reason}. "
                "Call query_athena again with corrected SQL."
            )},
        ]
        resp = _converse(SQL_SYSTEM, to_converse_messages(convo),
                         tool_config=QUERY_TOOL, model_id=req.model_id)
        tool = _tool_input(resp, "query_athena")
        if tool is None:
            break
        sql = _clean_sql(tool.get("sql", ""))
        ok, reason = validate_sql(sql)
    if not ok:
        raise HTTPException(422, f"could not produce a safe query: {reason}")

    # Persist only the user turn now; the assistant's result is appended by
    # /api/results after Athena runs, so memory reflects the actual returned data.
    history_append(req.session_id, "user", req.question)

    # Best-effort plain-language explanation; never fail generation if it errors.
    explanation = ""
    try:
        explanation = _invoke(
            EXPLAIN_SYSTEM, f"Question: {req.question}\n\nSQL:\n{sql}", max_tokens=256, model_id=req.model_id
        )
    except HTTPException:
        explanation = ""
    return {"sql": sql, "explanation": explanation, "session_id": req.session_id}


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
def get_results(execution_id: str = Path(min_length=8), question: str = "",
                model_id: str = "", session_id: str = ""):
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

    # Append the result to conversation memory so follow-up questions can reason
    # over what was actually returned (a compact assistant turn, not raw rows).
    if session_id:
        mem = f"Results for the question: {question}\nSummary: {summary}"
        if flags:
            mem += "\nFlags: " + "; ".join(str(f) for f in flags)
        if rows:
            mem += "\nSample rows (JSON): " + json.dumps(rows[:20], default=str)[:4000]
        history_append(session_id, "assistant", mem)

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
