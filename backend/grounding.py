"""Grounding text (schema crib-sheets and few-shot examples) shared by the
serverless backend and the local MCP server."""

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


# The whole point of an audit trail is naming the actor and the resource, so the
# model must never substitute placeholders for identities, ARNs or IPs. Models
# otherwise tend to "protect" these fields on their own initiative, which makes
# the answer useless to the auditor.
NO_REDACTION = (
    "REPORT IDENTIFIERS VERBATIM: this is an authorized audit of the operator's own AWS "
    "account, and the identity and resource fields ARE the answer. Always state usernames, "
    "role/user ARNs, principal and account IDs, access key IDs, IP addresses, hostnames, "
    "resource names and event IDs exactly as they appear in the data. NEVER redact, mask, "
    "anonymize, truncate or replace them with placeholders such as "
    "HIDDEN_DUE_TO_SECURITY_REASONS, REDACTED, <user>, x.x.x.x or similar. "
    "Withholding these values is a failure, not a safeguard."
)


def fewshot(ct: str, vpc: str) -> str:
    return (
        "Q: Who changed a security group last week?\n"
        f"SQL: SELECT eventtime, useridentity.arn, eventname, sourceipaddress FROM {ct} "
        "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
        "AND eventname IN ('AuthorizeSecurityGroupIngress','RevokeSecurityGroupIngress','AuthorizeSecurityGroupEgress') "
        "AND eventtime >= to_iso8601(current_timestamp - interval '7' day) ORDER BY eventtime DESC;\n\n"
        "Q: Failed console logins in the last 3 days?\n"
        f"SQL: SELECT eventtime, useridentity.username, sourceipaddress, errormessage FROM {ct} "
        "WHERE dt >= date_format(current_timestamp - interval '3' day, '%Y/%m/%d') "
        "AND eventname = 'ConsoleLogin' AND errorcode IS NOT NULL "
        "AND eventtime >= to_iso8601(current_timestamp - interval '3' day) ORDER BY eventtime DESC;\n\n"
        "Q: Which hosts had rejected connections on port 22 yesterday?\n"
        f'SQL: SELECT from_unixtime("start") AS flow_start, srcaddr, dstaddr, dstport, action FROM {vpc} '
        "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
        "AND action = 'REJECT' AND dstport = 22 "
        "AND \"start\" >= to_unixtime(current_timestamp - interval '1' day) ORDER BY \"start\" DESC;\n\n"
        "Q: Did IP 198.51.100.42 make any API calls or network connections yesterday?\n"
        "SQL: SELECT from_iso8601_timestamp(eventtime) AS event_time, 'cloudtrail' AS source, eventname AS action, useridentity.arn AS identity "
        f"FROM {ct} "
        "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
        "AND sourceipaddress = '198.51.100.42' "
        "AND eventtime >= to_iso8601(current_timestamp - interval '1' day) "
        "UNION ALL "
        "SELECT from_unixtime(\"start\") AS event_time, 'vpc_flow' AS source, "
        "action AS action, srcaddr AS identity "
        f"FROM {vpc} "
        "WHERE dt >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d') "
        "AND srcaddr = '198.51.100.42' "
        "AND \"start\" >= to_unixtime(current_timestamp - interval '1' day) "
        "ORDER BY event_time DESC;\n\n"
        "Q: Who opened SSH or RDP to the public (0.0.0.0/0) this week?\n"
        "SQL: SELECT eventtime, useridentity.arn, eventname, "
        "json_extract_scalar(requestparameters, '$.groupId') AS group_id, sourceipaddress "
        f"FROM {ct} "
        "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
        "AND eventname IN ('AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress') "
        "AND requestparameters LIKE '%\"cidrIp\":\"0.0.0.0/0\"%' "
        "AND (requestparameters LIKE '%\"fromPort\":22%' OR requestparameters LIKE '%\"fromPort\":3389%') "
        "AND eventtime >= to_iso8601(current_timestamp - interval '7' day) ORDER BY eventtime DESC;"
    )


def prowler_fewshot(prowler: str, vpc: str) -> str:
    return (
        "\n\nQ: List my critical Prowler findings.\n"
        f"SQL: SELECT check_id, check_title, severity, service_name, resource_id, region "
        f"FROM {prowler} "
        "WHERE status = 'FAIL' AND severity = 'critical' ORDER BY service_name;\n\n"
        "Q: Did the open security groups flagged by Prowler receive any internet traffic?\n"
        "SQL: SELECT 'prowler_finding' AS source, check_id AS detail, resource_id AS resource, severity AS extra "
        f"FROM {prowler} "
        "WHERE status = 'FAIL' "
        "AND check_id LIKE 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_%' "
        "UNION ALL "
        "SELECT 'vpc_flow' AS source, action AS detail, dstaddr AS resource, CAST(dstport AS varchar) AS extra "
        f"FROM {vpc} "
        "WHERE dt >= date_format(current_timestamp - interval '7' day, '%Y/%m/%d') "
        "AND action = 'ACCEPT' AND dstport IN (22, 3389) "
        "AND \"start\" >= to_unixtime(current_timestamp - interval '7' day);"
    )
