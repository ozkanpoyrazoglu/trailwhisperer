"""Estimate how many bytes Athena will scan, before the query runs.

CloudTrail and VPC Flow Logs land in S3 as gzipped JSON/text, not a columnar
format. Athena cannot skip columns inside those files, so a query reads every
object in the partitions it touches, and Athena bills on those compressed bytes.
That makes the estimate simple and honest: work out which (account, region, dt)
partitions the SQL selects, then add up the sizes of the S3 objects under them.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from sqlglot import exp

from . import guardrail

ATHENA_USD_PER_TB = 5.0          # us-east-1 list price; most Regions match
ATHENA_MIN_BYTES = 10 * 1024**2  # Athena bills at least 10 MB per query
MAX_PREFIXES = 3000              # refuse to estimate absurdly wide scans


@dataclass
class TableLayout:
    """What partition projection tells us about where a table's files live."""
    name: str
    template: str                 # e.g. s3://bucket/AWSLogs/${account}/CloudTrail/${region}/${dt}
    accounts: list[str]
    regions: list[str]

    @classmethod
    def from_glue(cls, table: dict) -> "TableLayout":
        p = table.get("Parameters", {})
        return cls(
            name=table["Name"].lower(),
            template=p["storage.location.template"],
            accounts=[v.strip() for v in p.get("projection.account.values", "").split(",") if v.strip()],
            regions=[v.strip() for v in p.get("projection.region.values", "").split(",") if v.strip()],
        )


@dataclass
class ScanPlan:
    table: str
    accounts: list[str]
    regions: list[str]
    start: date
    end: date

    @property
    def days(self) -> int:
        return (self.end - self.start).days + 1


@dataclass
class Estimate:
    bytes: int | None
    plans: list[ScanPlan] = field(default_factory=list)
    prefixes: int = 0
    objects: int = 0
    note: str = ""

    @property
    def usd(self) -> float | None:
        if self.bytes is None:
            return None
        return max(self.bytes, ATHENA_MIN_BYTES) / 1e12 * ATHENA_USD_PER_TB

    def as_dict(self) -> dict:
        return {
            "estimated_scan_bytes": self.bytes,
            "estimated_scan_mb": None if self.bytes is None else round(self.bytes / 1024**2, 2),
            "estimated_cost_usd": None if self.usd is None else round(self.usd, 6),
            "s3_prefixes_listed": self.prefixes,
            "s3_objects": self.objects,
            "partitions": [
                {"table": p.table, "from": p.start.strftime("%Y/%m/%d"), "to": p.end.strftime("%Y/%m/%d"),
                 "days": p.days, "accounts": p.accounts, "regions": p.regions}
                for p in self.plans
            ],
            "note": self.note,
        }


# --- Reading partition bounds out of the SQL ----------------------------------
# The dt range comes from guardrail.dt_bounds, the same function the guardrail
# uses, so the estimator can't read a query differently from the check that let it through.

def _literal_filter(select: exp.Select, column: str) -> list[str] | None:
    """Values a select pins a partition column to (`col = 'x'` or `col IN ('x','y')`),
    else None, meaning every projected value is scanned."""
    values: set[str] | None = None
    for cmp in guardrail.binding_predicates(select, column, kinds=(exp.EQ, exp.In)):
        if isinstance(cmp, exp.In):
            if not guardrail._is_column(cmp.this, column) or cmp.args.get("query"):
                continue
            vals = {e.this for e in cmp.expressions if isinstance(e, exp.Literal) and e.is_string}
            if len(vals) != len(cmp.expressions):
                continue
        else:
            other = cmp.expression if guardrail._is_column(cmp.this, column) else cmp.this
            if not (isinstance(other, exp.Literal) and other.is_string):
                continue
            vals = {other.this}
        values = vals if values is None else values & vals
    return sorted(values) if values else None


def plan(sql: str, layouts: dict[str, TableLayout], today: date | None = None) -> list[ScanPlan]:
    """One ScanPlan per (select, log table) the statement reads. Raises ValueError
    when a scanning select has no canonical dt range."""
    today = today or datetime.now(timezone.utc).date()
    stmt = guardrail.parse_one(sql)
    plans = []
    for select in stmt.find_all(exp.Select):
        for table in sorted(guardrail.own_tables(select) & set(layouts)):
            layout = layouts[table]
            rng = guardrail.dt_bounds(select, today)  # raises ValueError on non-canonical dt
            accounts = _literal_filter(select, "account") or layout.accounts
            regions = _literal_filter(select, "region") or layout.regions
            plans.append(ScanPlan(table, accounts, regions, rng[0], rng[1]))
    return plans


# --- Sizing the partitions in S3 ----------------------------------------------

def prefixes_for(p: ScanPlan, layout: TableLayout) -> list[tuple[str, str]]:
    out = []
    d = p.start
    while d <= p.end:
        for acct in p.accounts:
            for region in p.regions:
                uri = (layout.template.replace("${account}", acct).replace("${region}", region)
                       .replace("${dt}", d.strftime("%Y/%m/%d")))
                bucket, _, key = uri.removeprefix("s3://").partition("/")
                out.append((bucket, key.rstrip("/") + "/"))
        d += timedelta(days=1)
    return out


def _prefix_size(s3, bucket: str, prefix: str) -> tuple[int, int]:
    total = count = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            total += obj["Size"]
            count += 1
    return total, count


def estimate(sql: str, layouts: dict[str, TableLayout], s3, today: date | None = None) -> Estimate:
    try:
        plans = plan(sql, layouts, today)
    except ValueError as e:
        return Estimate(bytes=None, note=str(e))
    prefixes = [pre for p in plans for pre in prefixes_for(p, layouts[p.table])]
    if len(prefixes) > MAX_PREFIXES:
        return Estimate(bytes=None, plans=plans, prefixes=len(prefixes),
                        note=f"{len(prefixes)} partitions is too wide to size; filter by region or narrow dt")
    with ThreadPoolExecutor(max_workers=16) as pool:
        sizes = list(pool.map(lambda bp: _prefix_size(s3, *bp), prefixes))
    return Estimate(
        bytes=sum(s for s, _ in sizes), plans=plans, prefixes=len(prefixes),
        objects=sum(c for _, c in sizes),
        note="Athena reads whole gzipped objects for these formats, so this is the bytes it will bill.",
    )
