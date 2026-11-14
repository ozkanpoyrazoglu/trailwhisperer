"""Guardrail unit tests for `validate_sql` (security findings H1/H2/M1 + basics).

Pure-parse tests — no AWS. Locks in the read-only/SELECT-only, mandatory-`dt`,
time-window-cap, CTE, and cross-database rules so a regression fails CI.
"""

import os

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ["ALLOWED_TIME_RANGE_MAX_DAYS"] = "90"
os.environ["GLUE_DATABASE"] = "trailwhisperer_db"
os.environ.pop("GLUE_PROWLER_TABLE", None)

import pytest  # noqa: E402

import main  # noqa: E402

# A `dt` bound within the 90-day cap, used to isolate the rule under test.
_RECENT = "date_format(current_timestamp - interval '7' day, '%Y/%m/%d')"


@pytest.mark.parametrize(
    "sql",
    [
        # canonical dynamic-window query
        f"SELECT eventtime FROM cloudtrail_logs WHERE dt >= {_RECENT} "
        "AND eventtime >= to_iso8601(current_timestamp - interval '7' day)",
        # read-only CTE (M1: CTE alias must not be treated as a non-whitelisted table)
        f"WITH x AS (SELECT eventtime, dt FROM cloudtrail_logs WHERE dt >= {_RECENT}) SELECT * FROM x",
        # DB-qualified with the correct database
        f"SELECT eventtime FROM trailwhisperer_db.cloudtrail_logs WHERE dt >= {_RECENT}",
        # UNION ALL with both log branches independently bound
        f"SELECT eventname AS a FROM cloudtrail_logs WHERE dt >= {_RECENT} "
        f'UNION ALL SELECT action AS a FROM vpc_flow_logs WHERE dt >= {_RECENT}',
        # recent literal dt bound (within cap)
        "SELECT eventtime FROM cloudtrail_logs WHERE dt >= '2999/01/01'",
        # reversed operands and an extra non-binding dt predicate are fine
        f"SELECT eventtime FROM cloudtrail_logs WHERE {_RECENT} <= dt",
        # UNNEST expands the same rows; it is not a second scan
        f"SELECT r.arn FROM cloudtrail_logs CROSS JOIN UNNEST(resources) AS t(r) WHERE dt >= {_RECENT}",
        # dt qualified with the log table's alias
        f"SELECT c.eventname FROM cloudtrail_logs c WHERE c.dt >= {_RECENT}",
        # unaliased table qualified with its own name
        f"SELECT eventname FROM cloudtrail_logs WHERE cloudtrail_logs.dt >= {_RECENT}",
        # dt under OR alongside a binding AND predicate
        f"SELECT eventtime FROM cloudtrail_logs WHERE dt >= {_RECENT} AND (dt = '2999/01/01' OR eventname = 'x')",
    ],
)
def test_accepts_safe_queries(sql):
    ok, reason = main.validate_sql(sql)
    assert ok, reason


@pytest.mark.parametrize(
    "sql",
    [
        # write statements
        "DROP TABLE cloudtrail_logs",
        "INSERT INTO cloudtrail_logs VALUES (1)",
        # non-whitelisted table
        f"SELECT * FROM secrets WHERE dt >= {_RECENT}",
        # M1: cross-database reference to a whitelisted bare name
        f"SELECT * FROM otherdb.cloudtrail_logs WHERE dt >= {_RECENT}",
        # H2: time column merely present, not a binding partition filter
        "SELECT * FROM cloudtrail_logs WHERE eventtime IS NOT NULL",
        # H2: dt bound only inside a subquery, outer scan unpruned
        "SELECT * FROM cloudtrail_logs WHERE eventname IN "
        "(SELECT eventname FROM cloudtrail_logs WHERE dt >= '2026/07/01')",
        # H2: dt bound under an OR (Athena won't prune across OR)
        "SELECT * FROM cloudtrail_logs WHERE eventname = 'x' OR dt >= '2026/07/01'",
        # H1: literal dt window older than the cap
        "SELECT * FROM cloudtrail_logs WHERE dt >= '2000/01/01'",
        # H1: dynamic window longer than the cap
        "SELECT * FROM cloudtrail_logs WHERE dt >= "
        "date_format(current_timestamp - interval '3650' day, '%Y/%m/%d')",
        # H1: BETWEEN reaching back beyond the cap
        "SELECT * FROM cloudtrail_logs WHERE dt BETWEEN '2000/01/01' AND '2026/07/01'",
        # UNION ALL with one branch unbound
        f"SELECT eventname AS a FROM cloudtrail_logs WHERE dt >= {_RECENT} "
        "UNION ALL SELECT action AS a FROM vpc_flow_logs WHERE action = 'ACCEPT'",
        # Non-canonical dt bounds that used to count as "binding" but prune nothing:
        "SELECT * FROM cloudtrail_logs WHERE dt > ''",                         # empty string
        "SELECT * FROM cloudtrail_logs WHERE dt >= dt",                        # tautology
        "SELECT * FROM cloudtrail_logs WHERE dt >= lower('x')",                # arbitrary function
        "SELECT * FROM cloudtrail_logs WHERE dt >= '2026/1/5'",                # not zero-padded
        "SELECT * FROM cloudtrail_logs WHERE substr(dt, 1, 4) >= '2026'",      # dt wrapped
        f"SELECT * FROM cloudtrail_logs WHERE NOT (dt < {_RECENT})",            # under NOT
        "SELECT * FROM cloudtrail_logs WHERE '2999/01/01' >= dt",              # upper bound only
        # summed intervals, each under the cap, together far beyond it
        "SELECT * FROM cloudtrail_logs WHERE dt >= date_format(current_timestamp - interval '80' day "
        "- interval '80' day, '%Y/%m/%d')",
        # one dt filter, two scans: the joined side is unbounded
        f"SELECT * FROM cloudtrail_logs a JOIN cloudtrail_logs b ON a.eventid = b.eventid WHERE a.dt >= {_RECENT}",
        f"SELECT * FROM cloudtrail_logs a, vpc_flow_logs b WHERE a.dt >= {_RECENT}",
        f"SELECT * FROM cloudtrail_logs a JOIN (SELECT * FROM vpc_flow_logs) b ON true WHERE a.dt >= {_RECENT}",
        # an UNNEST column named dt standing in for the partition key
        "SELECT * FROM cloudtrail_logs c CROSS JOIN UNNEST(ARRAY['2999/01/01']) AS t(dt) WHERE t.dt >= '2999/01/01'",
        f"SELECT * FROM cloudtrail_logs c CROSS JOIN UNNEST(resources) AS t(r) WHERE t.dt >= {_RECENT}",
        f"SELECT * FROM cloudtrail_logs c CROSS JOIN UNNEST(resources) AS c(r) WHERE c.dt >= {_RECENT}",
        # inner scan "bounded" by a correlated reference to the outer row's dt
        f"SELECT * FROM cloudtrail_logs WHERE dt >= {_RECENT} AND eventid IN "
        f"(SELECT eventid FROM cloudtrail_logs c WHERE cloudtrail_logs.dt >= {_RECENT})",
    ],
)
def test_rejects_unsafe_queries(sql):
    ok, _ = main.validate_sql(sql)
    assert not ok
