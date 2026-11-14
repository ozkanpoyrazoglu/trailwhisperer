"""Parse-based SQL guardrail shared by the serverless backend and the local MCP server.

Pure Python + sqlglot: no AWS calls, no environment reads. Callers pass the
table whitelist and limits explicitly, so the same rules run in Lambda and on a
laptop.
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

import sqlglot
from sqlglot import exp

# A `dt` predicate that actually prunes partitions must narrow the scan: a lower
# bound (>=/>), an exact match (=/IN), or a range (BETWEEN). Upper-bound-only
# (</<=), IS [NOT] NULL, LIKE and <> do NOT bound how far back Athena scans, so
# they don't count as binding.
_DT_BINDING = (exp.GTE, exp.GT, exp.EQ, exp.Between, exp.In)
UNIT_DAYS = {
    "day": 1, "days": 1, "week": 7, "weeks": 7,
    "month": 30, "months": 30, "year": 365, "years": 365,
}
_FORBIDDEN = (
    exp.Insert, exp.Update, exp.Delete, exp.Create, exp.Drop,
    exp.Alter, exp.Merge, exp.Command,
)


@dataclass(frozen=True)
class Policy:
    database: str
    time_partitioned: frozenset[str]          # log tables that MUST bind `dt`
    static_tables: frozenset[str] = field(default_factory=frozenset)  # e.g. Prowler snapshot
    max_days: int = 90

    @property
    def allowed(self) -> frozenset[str]:
        return self.time_partitioned | self.static_tables


def parse_one(sql: str) -> exp.Expression:
    """Parse exactly one Trino statement or raise ValueError."""
    try:
        statements = [s for s in sqlglot.parse(sql, dialect="trino") if s]
    except Exception as e:  # sqlglot raises several error types
        raise ValueError(f"could not parse SQL: {e}") from e
    if len(statements) != 1:
        raise ValueError("exactly one statement is allowed")
    return statements[0]


def own_tables(select: exp.Select) -> set[str]:
    """Table names in THIS select's own FROM/joins (not nested subqueries)."""
    return {
        t.name.lower()
        for t in select.find_all(exp.Table)
        if t.name and t.find_ancestor(exp.Select) is select
    }


def under_or(node: exp.Expression, where: exp.Where) -> bool:
    """True if `node` sits under an OR between it and its WHERE — such a
    predicate can't be relied on to prune (Athena won't prune across an OR)."""
    p = node.parent
    while p is not None and p is not where:
        if isinstance(p, exp.Or):
            return True
        p = p.parent
    return False


def binding_predicates(select: exp.Select, column: str, kinds=_DT_BINDING):
    """Comparisons on `column` in AND context of this select's own WHERE."""
    where = select.args.get("where")
    if not where:
        return []
    out = []
    for cmp in where.find_all(*kinds):
        if cmp.find_ancestor(exp.Select) is not select or under_or(cmp, where):
            continue
        if any(c.name.lower() == column and c.find_ancestor(exp.Select) is select
               for c in cmp.find_all(exp.Column)):
            out.append(cmp)
    return out


def interval_days(iv: exp.Interval) -> int | None:
    """Days spanned by `interval 'N' <unit>`; 0 for sub-day units, None if unknown."""
    unit_node = iv.args.get("unit")
    unit = unit_node.name.lower() if unit_node else ""
    factor = UNIT_DAYS.get(unit)
    try:
        n = int(iv.this.name)
    except (AttributeError, ValueError):
        return None
    if factor is None:
        return 0  # hour/minute/second windows never exceed a day-based cap
    return n * factor


def dt_literal(lit: exp.Literal) -> date | None:
    if not lit.is_string:
        return None
    try:
        return datetime.strptime(lit.this, "%Y/%m/%d").date()
    except ValueError:
        return None


def validate(sql: str, policy: Policy):
    """Returns (ok, reason). Never raises."""
    try:
        stmt = parse_one(sql)
    except ValueError as e:
        return False, str(e)
    if any(stmt.find(f) for f in _FORBIDDEN):
        return False, "only read-only SELECT statements are allowed"
    if not isinstance(stmt, (exp.Select, exp.Union)):
        return False, "query must be a SELECT"

    # CTE names are local aliases, not real tables.
    cte_names = {c.alias_or_name.lower() for c in stmt.find_all(exp.CTE) if c.alias_or_name}
    real_tables = [t for t in stmt.find_all(exp.Table) if t.name and t.name.lower() not in cte_names]
    tables = {t.name.lower() for t in real_tables}
    if not tables:
        return False, "query must scan a whitelisted table"
    if tables - policy.allowed:
        allowed_list = "`, `".join(sorted(policy.allowed))
        return False, f"only tables `{allowed_list}` may be queried"
    for t in real_tables:
        if t.db and t.db.lower() != policy.database.lower():
            return False, "cross-database table references are not allowed"

    # EVERY select that scans a log table must bind `dt` itself, in AND context.
    earliest = (datetime.now(timezone.utc) - timedelta(days=policy.max_days)).date()
    scanning = [s for s in stmt.find_all(exp.Select) if own_tables(s) & policy.time_partitioned]
    for s in scanning:
        preds = binding_predicates(s, "dt")
        if not preds:
            return False, (
                "WHERE must bind the `dt` partition key with a range/equality filter "
                "in AND context (not under OR, not only in a subquery), e.g. "
                "dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')"
            )
        for cmp in preds:
            for lit in cmp.find_all(exp.Literal):
                d = dt_literal(lit)
                if d and d < earliest:
                    return False, f"the `dt` window reaches further back than the {policy.max_days}-day maximum"

    for iv in stmt.find_all(exp.Interval):
        days = interval_days(iv)
        if days and days > policy.max_days:
            return False, f"time window exceeds the {policy.max_days}-day maximum"

    return True, None
