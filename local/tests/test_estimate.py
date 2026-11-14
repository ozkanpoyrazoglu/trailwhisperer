"""Partition-range extraction and S3 sizing for the scan estimator (no AWS)."""

from datetime import date

import pytest

from trailwhisperer_local import estimate as est

TODAY = date(2026, 11, 14)
CT = est.TableLayout(
    name="cloudtrail_logs",
    template="s3://trail-bucket/AWSLogs/${account}/CloudTrail/${region}/${dt}",
    accounts=["111122223333"],
    regions=["us-east-1", "eu-west-1"],
)
VPC = est.TableLayout(
    name="vpc_flow_logs",
    template="s3://flow-bucket/AWSLogs/${account}/vpcflowlogs/${region}/${dt}",
    accounts=["111122223333"],
    regions=["eu-west-1"],
)
LAYOUTS = {"cloudtrail_logs": CT, "vpc_flow_logs": VPC}
DYN7 = "date_format(current_timestamp - interval '7' day, '%Y/%m/%d')"


def one(sql):
    plans = est.plan(sql, LAYOUTS, TODAY)
    assert len(plans) == 1
    return plans[0]


def test_dynamic_window_covers_n_days_back_to_today():
    p = one(f"SELECT 1 FROM cloudtrail_logs WHERE dt >= {DYN7}")
    assert (p.start, p.end, p.days) == (date(2026, 11, 7), TODAY, 8)
    assert p.regions == ["us-east-1", "eu-west-1"]


def test_literal_between_and_region_filter():
    p = one("SELECT 1 FROM cloudtrail_logs WHERE dt BETWEEN '2026/11/01' AND '2026/11/03' AND region = 'eu-west-1'")
    assert (p.start, p.end, p.regions) == (date(2026, 11, 1), date(2026, 11, 3), ["eu-west-1"])


def test_upper_bound_narrows_range():
    p = one(f"SELECT 1 FROM cloudtrail_logs WHERE dt >= {DYN7} AND dt <= '2026/11/09'")
    assert (p.start, p.end) == (date(2026, 11, 7), date(2026, 11, 9))


def test_equality_and_in():
    assert one("SELECT 1 FROM cloudtrail_logs WHERE dt = '2026/11/10'").days == 1
    p = one("SELECT 1 FROM cloudtrail_logs WHERE dt IN ('2026/11/10','2026/11/12') AND region IN ('us-east-1')")
    assert (p.start, p.end, p.regions) == (date(2026, 11, 10), date(2026, 11, 12), ["us-east-1"])


def test_sub_day_interval_reaches_into_yesterday():
    p = one("SELECT 1 FROM cloudtrail_logs WHERE dt >= date_format(current_timestamp - interval '6' hour, '%Y/%m/%d')")
    assert p.start == date(2026, 11, 13)


def test_union_plans_each_branch():
    sql = (f"SELECT eventname AS a FROM cloudtrail_logs WHERE dt >= {DYN7} UNION ALL "
           "SELECT action AS a FROM vpc_flow_logs WHERE dt = '2026/11/14'")
    plans = est.plan(sql, LAYOUTS, TODAY)
    assert sorted((p.table, p.days) for p in plans) == [("cloudtrail_logs", 8), ("vpc_flow_logs", 1)]


def test_unresolvable_range_raises():
    with pytest.raises(ValueError):
        est.plan("SELECT 1 FROM cloudtrail_logs WHERE dt >= some_udf()", LAYOUTS, TODAY)


def test_prefixes_expand_template():
    p = one("SELECT 1 FROM cloudtrail_logs WHERE dt = '2026/11/10' AND region = 'eu-west-1'")
    assert est.prefixes_for(p, CT) == [("trail-bucket", "AWSLogs/111122223333/CloudTrail/eu-west-1/2026/11/10/")]


class FakeS3:
    """list_objects_v2 paginator over an in-memory {(bucket, key): size} map."""

    def __init__(self, objects):
        self.objects = objects
        self.prefixes = []

    def get_paginator(self, _name):
        return self

    def paginate(self, Bucket, Prefix):
        self.prefixes.append(Prefix)
        yield {"Contents": [{"Key": k, "Size": v} for (b, k), v in self.objects.items()
                            if b == Bucket and k.startswith(Prefix)]}


def test_estimate_sums_object_sizes_and_prices_with_minimum():
    s3 = FakeS3({
        ("trail-bucket", "AWSLogs/111122223333/CloudTrail/eu-west-1/2026/11/13/a.json.gz"): 3 * 1024**2,
        ("trail-bucket", "AWSLogs/111122223333/CloudTrail/eu-west-1/2026/11/14/b.json.gz"): 2 * 1024**2,
        ("trail-bucket", "AWSLogs/111122223333/CloudTrail/eu-west-1/2026/11/01/old.json.gz"): 99 * 1024**2,
    })
    e = est.estimate("SELECT 1 FROM cloudtrail_logs WHERE dt >= date_format(current_timestamp - interval '1' day, "
                     "'%Y/%m/%d') AND region = 'eu-west-1'", LAYOUTS, s3, TODAY)
    assert e.bytes == 5 * 1024**2 and e.objects == 2 and e.prefixes == 2
    assert e.usd == pytest.approx(10 * 1024**2 / 1e12 * 5)  # 10 MB minimum applies


def test_too_wide_scan_is_not_estimated():
    wide = est.TableLayout("cloudtrail_logs", CT.template, [str(i) for i in range(40)], [f"r{i}" for i in range(17)])
    e = est.estimate(f"SELECT 1 FROM cloudtrail_logs WHERE dt >= {DYN7}", {"cloudtrail_logs": wide}, FakeS3({}), TODAY)
    assert e.bytes is None and "too wide" in e.note
