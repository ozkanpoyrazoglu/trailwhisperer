"""Parse-based SQL guardrail shared by the serverless backend and the local MCP server.

Pure Python + sqlglot: no AWS calls, no environment reads. Callers pass the
table whitelist and limits explicitly, so the same rules run in Lambda and on a
laptop.
"""

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

import sqlglot
from sqlglot import exp

# A `dt` predicate that actually prunes partitions must narrow the scan: a lower
# bound (>=/>), an exact match (=/IN), or a range (BETWEEN). Upper-bound-only
# (</<=), IS [NOT] NULL, LIKE and <> do NOT bound how far back Athena scans, so
# they don't count as binding.
_DT_BINDING = (exp.GTE, exp.GT, exp.EQ, exp.Between, exp.In, exp.LTE, exp.LT)
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


def predicate_context(node: exp.Expression, where: exp.Where) -> str:
    """'and' if only AND/parentheses sit between `node` and its WHERE, 'or' if an OR
    does (Athena can't prune across it, and it can only widen the match), else
    'other' (NOT, CASE, function calls...), whose effect on the scan we don't model."""
    p, seen_or = node.parent, False
    while p is not None and p is not where:
        if isinstance(p, exp.Or):
            seen_or = True
        elif not isinstance(p, (exp.And, exp.Paren)):
            return "other"
        p = p.parent
    return "or" if seen_or else "and"


def binding_predicates(select: exp.Select, column: str, kinds=_DT_BINDING):
    """Comparisons whose operand is the bare `column`, in pure AND context of
    this select's own WHERE (not nested subqueries, not under OR or NOT)."""
    where = select.args.get("where")
    if not where:
        return []
    out = []
    for cmp in where.find_all(*kinds):
        if cmp.find_ancestor(exp.Select) is not select or predicate_context(cmp, where) != "and":
            continue
        operands = [cmp.this] + ([cmp.expression] if isinstance(cmp, exp.Binary) else [])
        if any(_is_column(o, column) for o in operands):
            out.append(cmp)
    return out


def _is_column(node, column: str) -> bool:
    return isinstance(node, exp.Column) and node.name.lower() == column


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


_DT_RE = re.compile(r"\d{4}/\d{2}/\d{2}")
_NOW = (exp.CurrentTimestamp, exp.CurrentDate)


def dt_literal(lit: exp.Expression) -> date | None:
    """A zero-padded 'yyyy/MM/dd' string literal, exactly as the partitions are named."""
    if not (isinstance(lit, exp.Literal) and lit.is_string and _DT_RE.fullmatch(lit.this)):
        return None
    try:
        return datetime.strptime(lit.this, "%Y/%m/%d").date()
    except ValueError:
        return None


def resolve_dt_bound(node: exp.Expression, today: date) -> date | None:
    """The only two shapes a `dt` bound may take:
        'yyyy/MM/dd'
        date_format(current_timestamp [- interval 'N' unit], '%Y/%m/%d')
    Anything else (arithmetic on intervals, other functions, columns) is None."""
    if isinstance(node, exp.Literal):
        return dt_literal(node)
    if not isinstance(node, exp.TimeToStr):
        return None
    fmt = node.args.get("format")
    if not (isinstance(fmt, exp.Literal) and fmt.this == "%Y/%m/%d"):
        return None
    inner = node.this
    if isinstance(inner, _NOW):
        return today
    if isinstance(inner, exp.Sub) and isinstance(inner.this, _NOW) and isinstance(inner.expression, exp.Interval):
        days = interval_days(inner.expression)
        if days is None:
            return None
        return today - timedelta(days=days or 1)  # sub-day windows can reach into yesterday
    return None


_DT_REQUIRED = (
    "WHERE must bind the `dt` partition key with a range/equality filter "
    "in AND context (not under OR, not only in a subquery), e.g. "
    "dt >= date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')"
)
_DT_SHAPE = (
    "compare the bare `dt` column only to a 'yyyy/MM/dd' literal or to "
    "date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')"
)


def dt_bounds(select: exp.Select, today: date) -> tuple[date, date]:
    """[start, end] of the `dt` partitions this select reads. Raises ValueError
    unless every AND-context `dt` predicate has a canonical shape and at least one
    sets a lower bound. The guardrail and the scan estimator both call this, so
    they can never disagree about what a query reads."""
    where = select.args.get("where")
    if not where:
        raise ValueError(_DT_REQUIRED)
    start, end = None, today
    for col in where.find_all(exp.Column):
        if col.name.lower() != "dt" or col.find_ancestor(exp.Select) is not select:
            continue
        cmp = col.parent
        ctx = predicate_context(cmp, where) if cmp is not where else "and"
        if ctx == "or":
            continue  # can't prune, can't widen what the AND bounds allow
        if ctx == "other" or not isinstance(cmp, (exp.GTE, exp.GT, exp.LTE, exp.LT, exp.EQ, exp.Between, exp.In)):
            raise ValueError(_DT_SHAPE)
        if isinstance(cmp, exp.Between):
            lo, hi = resolve_dt_bound(cmp.args["low"], today), resolve_dt_bound(cmp.args["high"], today)
            if cmp.this is not col or lo is None or hi is None:
                raise ValueError(_DT_SHAPE)
            start, end = max(start or lo, lo), min(end, hi)
        elif isinstance(cmp, exp.In):
            ds = [resolve_dt_bound(e, today) for e in cmp.expressions]
            if cmp.this is not col or cmp.args.get("query") or not ds or None in ds:
                raise ValueError(_DT_SHAPE)
            start, end = max(start or min(ds), min(ds)), min(end, max(ds))
        else:
            col_left = cmp.this is col
            other = cmp.expression if col_left else cmp.this
            d = resolve_dt_bound(other, today)
            if d is None:
                raise ValueError(_DT_SHAPE)
            if isinstance(cmp, exp.EQ):
                start, end = max(start or d, d), min(end, d)
            elif isinstance(cmp, (exp.GTE, exp.GT)) == col_left:   # dt >= x  or  x <= dt
                start = max(start or d, d)
            else:
                end = min(end, d)
    if start is None:
        raise ValueError(_DT_REQUIRED)
    return start, end


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

    # EVERY select that scans a log table must bind `dt` itself, in canonical form.
    today = datetime.now(timezone.utc).date()
    earliest = today - timedelta(days=policy.max_days)
    for sel in stmt.find_all(exp.Select):
        if not own_tables(sel) & policy.time_partitioned:
            continue
        # One unqualified `dt` filter can't be attributed to one of several tables,
        # so a SELECT that reads a log table reads only that table. UNNEST is fine:
        # it expands a column of the same rows and scans nothing new.
        if any(not isinstance(j.this, exp.Unnest) for j in sel.args.get("joins") or []):
            return False, ("a SELECT that reads a log table may not JOIN other tables; "
                           "correlate sources with UNION ALL instead")
        try:
            start, _ = dt_bounds(sel, today)
        except ValueError as e:
            return False, str(e)
        if start < earliest:
            return False, f"the `dt` window reaches further back than the {policy.max_days}-day maximum"

    for iv in stmt.find_all(exp.Interval):
        days = interval_days(iv)
        if days and days > policy.max_days:
            return False, f"time window exceeds the {policy.max_days}-day maximum"

    return True, None
