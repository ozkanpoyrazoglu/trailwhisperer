"""Zero-dependency mock backend for local frontend simulation.

Implements the exact TrailWhisperer API contract (auth + 3 endpoints) with
canned data, so the SPA can be driven end-to-end WITHOUT AWS (no Bedrock,
Athena, or Secrets Manager). Standard-library only — no FastAPI/boto3 needed.

    python3 backend/mock_server.py            # serves on :8000
    AUTH_TOKEN=mysecret PORT=8000 python3 backend/mock_server.py

Then open the frontend (http://localhost:8080) and paste the token printed
at startup. Every response mirrors what the real backend returns.
"""

import json
import os
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTH_TOKEN = os.getenv("AUTH_TOKEN", "tw_local_dev_token")
PORT = int(os.getenv("PORT", "8000"))
GLUE_TABLE = "cloudtrail_logs"
GLUE_VPC_TABLE = "vpc_flow_logs"
MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"

# Track poll counts per execution so results briefly report "running" first,
# letting the SPA show its polling spinner just like the real Athena flow.
_POLLS: dict[str, int] = {}
_QUESTIONS: dict[str, str] = {}


# --- Canned scenarios: keyword -> (sql, columns, rows, summary, flags) -------
def _scenario(question: str):
    q = question.lower()

    if re.search(r"login|console|signin|sign-in", q):
        sql = (
            "SELECT eventtime, useridentity.username, sourceipaddress, errormessage\n"
            f"FROM {GLUE_TABLE}\n"
            "WHERE eventname = 'ConsoleLogin' AND errorcode IS NOT NULL\n"
            "  AND eventtime >= to_iso8601(current_timestamp - interval '3' day)\n"
            "ORDER BY eventtime DESC"
        )
        cols = ["eventtime", "username", "sourceipaddress", "errormessage"]
        rows = [
            {"eventtime": "2026-07-16T02:14:55Z", "username": "admin", "sourceipaddress": "185.220.101.4", "errormessage": "Failed authentication"},
            {"eventtime": "2026-07-16T02:14:41Z", "username": "admin", "sourceipaddress": "185.220.101.4", "errormessage": "Failed authentication"},
            {"eventtime": "2026-07-16T02:14:22Z", "username": "admin", "sourceipaddress": "185.220.101.4", "errormessage": "Failed authentication"},
            {"eventtime": "2026-07-15T19:03:10Z", "username": "ops-dan", "sourceipaddress": "203.0.113.9", "errormessage": "Failed authentication"},
        ]
        summary = (
            "Four failed console logins occurred in the last 3 days. Three of them target the "
            "'admin' user within 33 seconds from a single Tor-exit-range IP (185.220.101.4), "
            "consistent with a brute-force attempt."
        )
        flags = ["3 rapid failures for 'admin' from a known Tor exit node", "Off-hours activity (02:14 UTC)"]
        return sql, cols, rows, summary, flags

    if re.search(r"\biam\b|policy|role|permission", q):
        sql = (
            "SELECT eventtime, useridentity.arn, eventname, requestparameters\n"
            f"FROM {GLUE_TABLE}\n"
            "WHERE eventsource = 'iam.amazonaws.com'\n"
            "  AND eventname IN ('PutUserPolicy','AttachRolePolicy','CreatePolicyVersion')\n"
            "  AND eventtime >= to_iso8601(current_timestamp - interval '1' day)\n"
            "ORDER BY eventtime DESC"
        )
        cols = ["eventtime", "arn", "eventname", "requestparameters"]
        rows = [
            {"eventtime": "2026-07-16T13:22:07Z", "arn": "arn:aws:iam::1234:user/contractor-lee", "eventname": "AttachRolePolicy", "requestparameters": '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}'},
            {"eventtime": "2026-07-16T09:05:44Z", "arn": "arn:aws:iam::1234:role/ci-deployer", "eventname": "PutUserPolicy", "requestparameters": '{"policyName":"inline-s3"}'},
        ]
        summary = (
            "Two IAM permission changes happened in the past 24 hours. Notably, contractor-lee "
            "attached the AWS-managed AdministratorAccess policy to a role — a privilege escalation "
            "worth reviewing."
        )
        flags = ["AdministratorAccess attached by a contractor principal", "Inline policy added to a CI role"]
        return sql, cols, rows, summary, flags

    if re.search(r"vpc|flow log|network|traffic|reject|port \d|inbound|outbound|connection", q):
        sql = (
            'SELECT from_unixtime("start") AS flow_start, srcaddr, dstaddr, dstport, action\n'
            f"FROM {GLUE_VPC_TABLE}\n"
            "WHERE action = 'REJECT' AND dstport = 22\n"
            "  AND \"start\" >= to_unixtime(current_timestamp - interval '1' day)\n"
            'ORDER BY "start" DESC'
        )
        cols = ["flow_start", "srcaddr", "dstaddr", "dstport", "action"]
        rows = [
            {"flow_start": "2026-07-16 03:11:52", "srcaddr": "185.220.101.4", "dstaddr": "10.0.2.15", "dstport": "22", "action": "REJECT"},
            {"flow_start": "2026-07-16 03:11:44", "srcaddr": "185.220.101.4", "dstaddr": "10.0.2.15", "dstport": "22", "action": "REJECT"},
            {"flow_start": "2026-07-16 03:11:31", "srcaddr": "45.155.205.233", "dstaddr": "10.0.2.15", "dstport": "22", "action": "REJECT"},
        ]
        summary = (
            "Repeated rejected SSH (port 22) connection attempts hit the internal host 10.0.2.15 "
            "in the last day, mostly from a single external IP (185.220.101.4) in a Tor exit range — "
            "consistent with automated SSH scanning against a closed port."
        )
        flags = ["Rejected SSH scan from a known Tor exit node", "Off-hours network activity (03:11 UTC)"]
        return sql, cols, rows, summary, flags

    if re.search(r"root", q):
        sql = (
            "SELECT eventtime, eventname, sourceipaddress, awsregion\n"
            f"FROM {GLUE_TABLE}\n"
            "WHERE useridentity.type = 'Root'\n"
            "  AND eventtime >= to_iso8601(current_timestamp - interval '30' day)\n"
            "ORDER BY eventtime DESC"
        )
        cols = ["eventtime", "eventname", "sourceipaddress", "awsregion"]
        rows = [
            {"eventtime": "2026-07-02T11:40:19Z", "eventname": "ConsoleLogin", "sourceipaddress": "198.51.100.77", "awsregion": "us-east-1"},
        ]
        summary = "The root account was used once this month — a single console login on 2026-07-02 from us-east-1. Root usage should be rare and closely audited."
        flags = ["Root account console login detected"]
        return sql, cols, rows, summary, flags

    # Default: security-group changes
    sql = (
        "SELECT eventtime, useridentity.arn, eventname, sourceipaddress\n"
        f"FROM {GLUE_TABLE}\n"
        "WHERE eventname IN ('AuthorizeSecurityGroupIngress','RevokeSecurityGroupIngress',"
        "'AuthorizeSecurityGroupEgress')\n"
        "  AND eventtime >= to_iso8601(current_timestamp - interval '7' day)\n"
        "ORDER BY eventtime DESC"
    )
    cols = ["eventtime", "arn", "eventname", "sourceipaddress"]
    rows = [
        {"eventtime": "2026-07-15T09:42:11Z", "arn": "arn:aws:iam::1234:user/ops-priya", "eventname": "AuthorizeSecurityGroupIngress", "sourceipaddress": "203.0.113.7"},
        {"eventtime": "2026-07-15T09:41:58Z", "arn": "arn:aws:iam::1234:user/ops-priya", "eventname": "RevokeSecurityGroupIngress", "sourceipaddress": "203.0.113.7"},
        {"eventtime": "2026-07-14T22:10:03Z", "arn": "arn:aws:iam::1234:role/deploy", "eventname": "AuthorizeSecurityGroupIngress", "sourceipaddress": "198.51.100.24"},
    ]
    summary = (
        "Two principals modified security-group ingress rules in the past week. The user ops-priya "
        "made a paired authorize/revoke change from 203.0.113.7 within seconds, while the deploy "
        "role opened ingress from a different address the night before."
    )
    flags = ["Off-hours change by deploy role (22:10 UTC)", "Rapid authorize→revoke pair from a single IP"]
    return sql, cols, rows, summary, flags


def _explain(question: str) -> str:
    """Plain-language rendering of the generated query for the local demo,
    mirroring the branches in _scenario()."""
    q = question.lower()
    if re.search(r"login|console|signin|sign-in", q):
        return ("Finds failed attempts to sign in to the AWS console over the last 3 days, "
                "showing who tried, the IP address they came from, and why each attempt failed.")
    if re.search(r"\biam\b|policy|role|permission", q):
        return ("Looks for changes to user and role permissions in the past 24 hours — such as "
                "policies being attached — so you can spot anyone gaining new access.")
    if re.search(r"vpc|flow log|network|traffic|reject|port \d|inbound|outbound|connection", q):
        return ("Lists network connection attempts to your internal hosts on the SSH port that were "
                "blocked in the last day, including where each attempt came from.")
    if re.search(r"root", q):
        return ("Checks for any use of the all-powerful root account over the past 30 days, "
                "showing what it did, when, and from where.")
    return ("Finds who created or changed firewall (security-group) rules in the past week, "
            "including when the change happened and the IP address behind it.")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quieter console
        print(f"  {self.command} {self.path} -> {args[1]}")

    # --- helpers ---
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "authorization, content-type")

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else auth
        return token == AUTH_TOKEN

    def _read_json(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    # --- routes ---
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/health":
            return self._send(200, {
                "status": "ok",
                "model": MODEL_ID,
                "tables": [f"trailwhisperer_db.{GLUE_TABLE}", f"trailwhisperer_db.{GLUE_VPC_TABLE}"],
            })

        m = re.match(r"^/api/results/([^/?]+)", self.path)
        if m:
            if not self._authed():
                return self._send(401, {"detail": "invalid or missing token"})
            eid = m.group(1)
            n = _POLLS.get(eid, 0)
            _POLLS[eid] = n + 1
            if n == 0:  # first poll: pretend Athena is still scanning
                return self._send(200, {"status": "running", "state": "RUNNING"})
            question = _QUESTIONS.get(eid, "")
            _, cols, rows, summary, flags = _scenario(question)
            return self._send(200, {
                "status": "succeeded",
                "columns": cols,
                "rows": rows,
                "row_count": len(rows),
                "truncated": False,
                "bytes_scanned": 48210432,
                "summary": summary,
                "flags": flags,
            })

        return self._send(404, {"detail": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {"detail": "invalid or missing token"})

        if self.path == "/api/generate-sql":
            data = self._read_json()
            question = (data.get("question") or "").strip()
            session_id = data.get("session_id")
            if len(question) < 3:
                return self._send(422, {"detail": "question too short"})
            time.sleep(0.6)  # feel like a real model round-trip
            # Agentic routing demo: conversational turns (greetings/thanks/meta
            # questions) are answered from "memory" as plain text; everything else
            # proposes a query for approval, mirroring the real Tool Use routing.
            if re.match(r"^(hi|hello|hey|thanks|thank you|who are you|what can you)\b", question.lower()):
                return self._send(200, {
                    "chat_response": (
                        "I'm your CloudTrail & VPC Flow Logs analyst. Ask me things like "
                        "\"failed console logins today\" and I'll draft a read-only query for "
                        "your approval, then summarize what the logs show."
                    ),
                    "session_id": session_id,
                })
            sql, *_ = _scenario(question)
            return self._send(200, {"sql": sql, "explanation": _explain(question), "session_id": session_id})

        if self.path == "/api/execute-sql":
            data = self._read_json()
            sql = (data.get("sql") or "")
            if "select" not in sql.lower():
                return self._send(422, {"detail": "rejected by guardrail: query must be a SELECT"})
            eid = uuid.uuid4().hex[:16]
            _POLLS[eid] = 0
            # Best-effort: remember the question via the SQL scenario for summary
            _QUESTIONS[eid] = sql
            return self._send(200, {"execution_id": eid})

        return self._send(404, {"detail": "not found"})


if __name__ == "__main__":
    print("─" * 58)
    print("  TrailWhisperer — MOCK backend (no AWS)")
    print(f"  Listening : http://localhost:{PORT}")
    print(f"  Auth token: {AUTH_TOKEN}")
    print("  Paste that token into the frontend's access modal.")
    print("─" * 58)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
