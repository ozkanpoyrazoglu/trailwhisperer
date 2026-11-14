"""Settings, read from environment variables so they can live in the MCP client config.

The defaults match what `trailwhisperer-local init` creates, so a typical setup only
needs AWS_PROFILE and AWS_REGION.
"""

import os
from dataclasses import dataclass

from . import guardrail

MANAGED_TAG = ("trailwhisperer:managed-by", "trailwhisperer-local")


@dataclass(frozen=True)
class Settings:
    region: str
    database: str
    cloudtrail_table: str
    vpc_table: str
    workgroup: str
    max_days: int
    max_scan_bytes: int      # refuse to start a query whose estimate is above this
    max_rows: int            # rows handed back to the model per query
    query_timeout_s: int

    @property
    def policy(self) -> guardrail.Policy:
        return guardrail.Policy(
            database=self.database,
            time_partitioned=frozenset({self.cloudtrail_table.lower(), self.vpc_table.lower()}),
            max_days=self.max_days,
        )


def _int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    return int(raw) if raw.strip() else default


def load() -> Settings:
    import boto3

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or boto3.Session().region_name or "us-east-1"
    return Settings(
        region=region,
        database=os.getenv("TW_DATABASE", "trailwhisperer_local"),
        cloudtrail_table=os.getenv("TW_CLOUDTRAIL_TABLE", "cloudtrail_logs"),
        vpc_table=os.getenv("TW_VPC_TABLE", "vpc_flow_logs"),
        workgroup=os.getenv("TW_WORKGROUP", "trailwhisperer-local"),
        max_days=_int("TW_MAX_DAYS", 30),
        max_scan_bytes=_int("TW_MAX_SCAN_BYTES", 1024**3),
        max_rows=_int("TW_MAX_ROWS", 200),
        query_timeout_s=_int("TW_QUERY_TIMEOUT", 90),
    )
