"""run_query refuses unsafe or unchecked SQL before anything reaches Athena (no AWS)."""

import pytest

from trailwhisperer_local import estimate as est
from trailwhisperer_local import server
from trailwhisperer_local.config import Settings

SETTINGS = Settings(region="eu-west-1", database="trailwhisperer_local", cloudtrail_table="cloudtrail_logs",
                    vpc_table="vpc_flow_logs", workgroup="tw", max_days=30, max_scan_bytes=50 * 1024**2,
                    max_rows=2, query_timeout_s=5)
LAYOUT = est.TableLayout("cloudtrail_logs", "s3://b/AWSLogs/${account}/CloudTrail/${region}/${dt}",
                         ["111122223333"], ["eu-west-1"])
OK_SQL = ("SELECT eventname FROM cloudtrail_logs WHERE dt >= "
          "date_format(current_timestamp - interval '1' day, '%Y/%m/%d')")


class FakeS3:
    def __init__(self, size):
        self.size = size

    def get_paginator(self, _):
        return self

    def paginate(self, Bucket, Prefix):
        yield {"Contents": [{"Key": Prefix + "x.gz", "Size": self.size}]}


class FakeAthena:
    def __init__(self):
        self.started = []

    def start_query_execution(self, **kw):
        self.started.append(kw)
        return {"QueryExecutionId": "q-123"}

    def get_query_execution(self, QueryExecutionId):
        return {"QueryExecution": {"Status": {"State": "SUCCEEDED"},
                                   "Statistics": {"DataScannedInBytes": 4 * 1024**2, "EngineExecutionTimeInMillis": 900}}}

    def get_paginator(self, _):
        return self

    def paginate(self, **_):
        meta = {"ColumnInfo": [{"Name": "eventname"}]}
        rows = [{"Data": [{"VarCharValue": v}]} for v in ("eventname", "A", "B", "C")]
        yield {"ResultSet": {"ResultSetMetadata": meta, "Rows": rows}}


@pytest.fixture
def fake(monkeypatch):
    athena = FakeAthena()
    s3 = FakeS3(1024**2)  # 1 MB per daily prefix -> 2 MB for a 1-day window
    monkeypatch.setattr(server, "settings", lambda: SETTINGS)
    monkeypatch.setattr(server, "layouts", lambda: {"cloudtrail_logs": LAYOUT})
    monkeypatch.setattr(server, "_athena", lambda: athena)
    monkeypatch.setattr(server, "_s3", lambda: s3)
    return athena, s3


def test_check_query_reports_estimate(fake):
    r = server.check_query(OK_SQL)
    assert r["allowed"] and r["estimated_scan_mb"] == 2.0 and r["s3_objects"] == 2


@pytest.mark.parametrize("sql", [
    "DROP TABLE cloudtrail_logs",
    "SELECT eventname FROM cloudtrail_logs",                                     # no dt
    "SELECT eventname FROM cloudtrail_logs WHERE dt >= '2026/01/01' OR 1=1",     # dt under OR
    "SELECT * FROM other_table WHERE dt = '2026/11/14'",                          # not whitelisted
    OK_SQL.replace("'1' day", "'365' day"),                                       # over max_days
])
def test_run_query_never_starts_unsafe_sql(fake, sql):
    athena, _ = fake
    r = server.run_query(sql, estimated_scan_mb=1, purpose="test")
    assert r["allowed"] is False and r["stage"] == "guardrail"
    assert athena.started == []


def test_run_query_requires_the_checked_estimate(fake):
    athena, _ = fake
    r = server.run_query(OK_SQL, estimated_scan_mb=500, purpose="test")
    assert r["stage"] == "estimate-mismatch" and athena.started == []


def test_run_query_refuses_scans_over_the_limit(fake):
    athena, s3 = fake
    s3.size = 40 * 1024**2  # 80 MB over two days > 50 MB limit
    r = server.run_query(OK_SQL, estimated_scan_mb=80, purpose="test")
    assert r["stage"] == "scan-limit" and athena.started == []


def test_run_query_runs_in_workgroup_and_caps_rows(fake):
    athena, _ = fake
    r = server.run_query(OK_SQL, estimated_scan_mb=2.0, purpose="test")
    assert athena.started[0]["WorkGroup"] == "tw"
    assert r["state"] == "SUCCEEDED" and r["rows"] == [{"eventname": "A"}, {"eventname": "B"}]
    assert r["truncated"] is True and r["scanned_mb"] == 4.0


def test_get_results_only_for_own_executions(fake):
    assert "unknown execution id" in server.get_results("someone-elses-query")["error"]


def test_unknown_estimate_fails_closed(fake, monkeypatch):
    athena, _ = fake
    monkeypatch.setattr(server.est, "estimate", lambda *a, **k: est.Estimate(bytes=None, note="too wide"))
    r = server.run_query(OK_SQL, estimated_scan_mb=0, purpose="test")
    assert r["allowed"] is False and r["stage"] == "estimate" and athena.started == []
