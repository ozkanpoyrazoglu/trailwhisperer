import functools
import hmac
import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from pydantic import BaseModel, Field

import guardrail
from grounding import CRIB, NO_REDACTION, PROWLER_CRIB, VPC_CRIB, fewshot, prowler_fewshot

logger = logging.getLogger("trailwhisperer")

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
# Client-side runaway-scan guard. Deployed workgroups also enforce this at the
# service level (BytesScannedCutoffPerQuery), but local/VM dev often runs against
# the `primary` workgroup which has no cutoff — so we additionally stop a running
# query here once its scanned bytes exceed the limit. 0/unset disables the guard.
BYTES_SCANNED_CUTOFF = int(os.getenv("BYTES_SCANNED_CUTOFF", "0") or "0")
MAX_DAYS = int(os.getenv("ALLOWED_TIME_RANGE_MAX_DAYS", "90"))
MAX_ROWS = 1000
SUMMARY_ROWS = 200
# Per-execution Bedrock summary cache so repeat result polls don't re-summarize (L2).
_SUMMARY_CACHE: dict[str, tuple] = {}
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


# Short-TTL cache for the Secrets Manager token. A warm Lambda/container must NOT
# cache the token for its whole lifetime (M4): after a secret rotation a warm
# container would keep accepting the stale token and reject the new one until a
# cold start. A 300s TTL bounds that window while still avoiding a Secrets Manager
# call on every request. The env-var token (local dev) never rotates.
_AUTH_TTL_SECONDS = 300
_auth_cache: dict = {"token": None, "expires": 0.0}


def auth_token():
    token = os.getenv("AUTH_TOKEN")
    if token:
        return token
    if _auth_cache["expires"] > time.time():
        return _auth_cache["token"]
    arn = os.getenv("AUTH_SECRET_ARN")
    resolved = None
    if arn:
        sm = boto3.client("secretsmanager", region_name=REGION)
        raw = sm.get_secret_value(SecretId=arn)["SecretString"]
        try:
            resolved = json.loads(raw)["token"]
        except (ValueError, KeyError):
            resolved = raw
    _auth_cache["token"] = resolved
    _auth_cache["expires"] = time.time() + _AUTH_TTL_SECONDS
    return resolved


def require_auth(authorization: str = Header(default="")):
    expected = auth_token()
    if not expected:
        raise HTTPException(500, "auth token not configured")
    presented = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(401, "invalid or missing token")


# --- Grounding -------------------------------------------------------------

FEWSHOT = fewshot(GLUE_TABLE, GLUE_VPC_TABLE)
PROWLER_FEWSHOT = prowler_fewshot(GLUE_PROWLER_TABLE, GLUE_VPC_TABLE) if GLUE_PROWLER_TABLE else ""

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
    f"{NO_REDACTION}\n"
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
    "sensitive API calls, off-hours activity. Empty list if nothing stands out. "
    "Keep it SHORT so the JSON always closes: at most 5 flags, each ONE sentence. Group "
    'repetition ("12 flows from 98.87.175.76") instead of listing every row. '
    f"{NO_REDACTION} Name the concrete principals, IPs and resources from the rows in both "
    "the summary and the flags."
)

# Plain-language rendering of the generated SQL, so a non-technical approver can
# understand what they are authorizing before it runs (human-in-the-loop).
EXPLAIN_SYSTEM = (
    "You explain an Athena SQL query to a NON-TECHNICAL auditor who does not read SQL. "
    "Given their question and the query, write 1-2 short plain-English sentences describing "
    "what the query looks for and the time window it covers. "
    "No SQL keywords, no table or column names, no markdown, no code — just a clear explanation. "
    "Name any specific user, IP or resource the query filters on verbatim; never mask it."
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
        # Don't echo the raw provider message to the client (M2): it can leak
        # model/region/config detail. Log it server-side, return a generic error.
        logger.warning("bedrock converse failed: %s", e.response["Error"].get("Message", str(e)))
        raise HTTPException(502, "the language model request failed")


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


# --- Guardrail ---------------------------------------------------------------
# The rules live in guardrail.py so the local MCP server enforces exactly the same
# checks. Here we only bind them to this deployment's tables and limits.

GUARDRAIL_POLICY = guardrail.Policy(
    database=GLUE_DATABASE,
    time_partitioned=frozenset({GLUE_TABLE.lower(), GLUE_VPC_TABLE.lower()}),
    static_tables=frozenset({GLUE_PROWLER_TABLE.lower()}) if GLUE_PROWLER_TABLE else frozenset(),
    max_days=MAX_DAYS,
)


def validate_sql(sql: str):
    """Parse-based guardrail. Returns (ok, reason)."""
    return guardrail.validate(sql, GUARDRAIL_POLICY)


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
        logger.warning("athena start_query_execution failed: %s", e.response["Error"].get("Message", str(e)))
        raise HTTPException(502, "failed to start the query")
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


def _salvage_summary_json(text: str):
    """Recover {summary, flags} from a reply whose JSON never closed — the model
    hit the max-tokens ceiling mid-object. Uses the stdlib JSON string scanner so
    escapes are handled, keeps every COMPLETE flag, and drops the partial one.
    Returns dict or None."""
    def _read_string_at(quote: int):
        """Decode the JSON string whose opening quote is at `quote`."""
        try:
            return json.decoder.scanstring(text, quote + 1)  # -> (value, end)
        except ValueError:
            return None

    def _value_quote(key: str) -> int:
        k = text.find(f'"{key}"')
        return -1 if k == -1 else text.find('"', k + len(key) + 2)

    summary, truncated = "", False
    q = _value_quote("summary")
    if q != -1:
        got = _read_string_at(q)
        if got:
            summary = got[0]
        else:
            # The summary itself was cut off — keep the readable prefix.
            summary = text[q + 1:].rstrip().rstrip("\\") + " […]"
            truncated = True

    flags = []
    k = text.find('"flags"')
    if k != -1:
        pos = text.find("[", k) + 1
        while pos > 0:
            q = text.find('"', pos)
            close = text.find("]", pos)
            if q == -1 or (close != -1 and close < q):
                break
            got = _read_string_at(q)
            if not got:
                truncated = True  # partial flag — drop it
                break
            flags.append(got[0])
            pos = got[1]

    if not summary and not flags:
        return None
    if truncated:
        flags.append("(This summary was cut short by the model's output limit; "
                     "the result rows above are complete.)")
    return {"summary": summary, "flags": flags}


def _parse_summary_json(text: str):
    """Extract the {summary, flags} object even if the model wraps it in
    markdown fences or surrounding prose, or never closed the JSON at all.
    Returns dict or None."""
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
            pass
    return _salvage_summary_json(text)


def _summarize(question: str, rows: list, model_id: str | None = None):
    sample = rows[:SUMMARY_ROWS]
    user = f"Question: {question or 'Summarize this CloudTrail activity.'}\n\nRows (JSON):\n{json.dumps(sample, default=str)}"
    # 800 tokens was not enough for a 200-row flow-log sample: the model ran out
    # mid-JSON, the object never closed, and the raw text leaked into the summary
    # panel unrendered. Verbose non-English narratives cost more tokens still.
    text = _invoke(SUMMARY_SYSTEM, user, max_tokens=2000, model_id=model_id)
    data = _parse_summary_json(text)
    if isinstance(data, dict):
        return data.get("summary", ""), data.get("flags", [])
    logger.warning("summary JSON unparseable (%d chars), returning raw text", len(text))
    return text, []


@app.get("/api/results/{execution_id}", dependencies=[Depends(require_auth)])
def get_results(execution_id: str = Path(min_length=8), question: str = "",
                model_id: str = "", session_id: str = ""):
    try:
        info = _athena().get_query_execution(QueryExecutionId=execution_id)["QueryExecution"]
    except ClientError as e:
        logger.warning("athena get_query_execution failed: %s", e.response["Error"].get("Message", str(e)))
        raise HTTPException(502, "failed to fetch query status")

    state = info["Status"]["State"]
    scanned = info.get("Statistics", {}).get("DataScannedInBytes")

    if state in ("QUEUED", "RUNNING"):
        # Client-side runaway-scan guard (H3): stop a still-running query once its
        # scanned bytes pass the cutoff. Deployed workgroups enforce this at the
        # service level, but a local `primary` workgroup has no cutoff.
        if BYTES_SCANNED_CUTOFF and scanned and scanned > BYTES_SCANNED_CUTOFF:
            try:
                _athena().stop_query_execution(QueryExecutionId=execution_id)
            except ClientError as e:
                logger.warning("athena stop_query_execution failed: %s", e)
            return {"status": "failed", "state": "CANCELLED",
                    "error": "query exceeded the configured scan limit and was stopped",
                    "bytes_scanned": scanned}
        return {"status": "running", "state": state}
    if state in ("FAILED", "CANCELLED"):
        # Don't echo Athena's raw StateChangeReason to the client (M2) — it can
        # leak schema/column names. Log it, return a generic failure.
        logger.info("athena query %s %s: %s", execution_id, state,
                    info["Status"].get("StateChangeReason", ""))
        return {"status": "failed", "state": state,
                "error": "the query did not complete successfully", "bytes_scanned": scanned}

    columns, rows = _fetch_rows(execution_id)

    # Cache the (expensive) Bedrock summary per execution_id (L2): the SPA polls
    # this endpoint and any repeat GET for a SUCCEEDED query would otherwise
    # re-invoke Bedrock. Cache the summary/flags, not the rows (re-fetching rows
    # from Athena is free). Conversation memory is written only on the first
    # summarization so repeat polls don't duplicate the turn.
    if not rows:
        summary, flags = ("No matching events were found.", [])
    elif execution_id in _SUMMARY_CACHE:
        summary, flags = _SUMMARY_CACHE[execution_id]
    else:
        summary, flags = _summarize(question, rows, model_id or None)
        if len(_SUMMARY_CACHE) >= 512:  # bound growth in a long-lived container
            _SUMMARY_CACHE.clear()
        _SUMMARY_CACHE[execution_id] = (summary, flags)

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
