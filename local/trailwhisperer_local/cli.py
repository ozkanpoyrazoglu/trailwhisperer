"""trailwhisperer-local: set up, check and tear down the few AWS objects the MCP server needs.

    init      Glue database + partition-projected tables over your existing log buckets,
              an Athena workgroup with a bytes-scanned cutoff, and a results bucket that
              expires objects after 7 days. No CloudFormation, nothing always-on.
    doctor    verify credentials, tables, workgroup and S3 access; estimate a 1-day query
    policy    print a least-privilege IAM policy for the identity the MCP server uses
    teardown  delete everything init created (your log buckets are never touched)
    serve     run the MCP server on stdio (what Claude Code / Claude Desktop launches)
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

from . import estimate as est
from .config import MANAGED_TAG, load

CT_COLUMNS = [
    ("eventversion", "string"),
    ("useridentity", "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,"
                     "accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<"
                     "mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,"
                     "principalid:string,arn:string,accountid:string,username:string>>>"),
    ("eventtime", "string"), ("eventsource", "string"), ("eventname", "string"),
    ("awsregion", "string"), ("sourceipaddress", "string"), ("useragent", "string"),
    ("errorcode", "string"), ("errormessage", "string"), ("requestparameters", "string"),
    ("responseelements", "string"), ("additionaleventdata", "string"), ("requestid", "string"),
    ("eventid", "string"), ("resources", "array<struct<arn:string,accountid:string,type:string>>"),
    ("eventtype", "string"), ("apiversion", "string"), ("readonly", "string"),
    ("recipientaccountid", "string"), ("serviceeventdetails", "string"),
    ("sharedeventid", "string"), ("vpcendpointid", "string"),
]
VPC_COLUMNS = [
    ("version", "int"), ("account_id", "string"), ("interface_id", "string"),
    ("srcaddr", "string"), ("dstaddr", "string"), ("srcport", "int"), ("dstport", "int"),
    ("protocol", "bigint"), ("packets", "bigint"), ("bytes", "bigint"),
    ("start", "bigint"), ("end", "bigint"), ("action", "string"), ("log_status", "string"),
]
PARTITIONS = [{"Name": "account", "Type": "string"}, {"Name": "region", "Type": "string"},
              {"Name": "dt", "Type": "string"}]


def _say(msg=""):
    print(msg, file=sys.stderr)


def _logs_root(bucket: str, prefix: str, org_id: str | None) -> str:
    root = "/".join(p for p in (prefix.strip("/"), "AWSLogs", org_id) if p)
    return f"{bucket}/{root}"


def _children(s3, bucket_and_prefix: str) -> list[str]:
    bucket, _, prefix = bucket_and_prefix.partition("/")
    names = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix + "/", Delimiter="/"):
        names += [c["Prefix"].rstrip("/").rsplit("/", 1)[-1] for c in page.get("CommonPrefixes", [])]
    return names


def _discover(s3, root: str, service: str, accounts: list[str] | None, regions: list[str] | None):
    """Projection values come from what is actually in the bucket, so the
    estimator never lists prefixes for Regions that have no logs."""
    accounts = accounts or [a for a in _children(s3, root) if a.isdigit()]
    if not regions:
        found = set()
        for a in accounts:
            found.update(_children(s3, f"{root}/{a}/{service}"))
        regions = sorted(found)
    return accounts, regions


def _table_input(name, root, service, accounts, regions, columns, vpc=False) -> dict:
    params = {
        "projection.enabled": "true",
        "projection.account.type": "enum", "projection.account.values": ",".join(accounts),
        "projection.region.type": "enum", "projection.region.values": ",".join(regions),
        "projection.dt.type": "date", "projection.dt.format": "yyyy/MM/dd",
        "projection.dt.range": "NOW-3YEARS,NOW", "projection.dt.interval": "1",
        "projection.dt.interval.unit": "DAYS",
        "storage.location.template": f"s3://{root}/${{account}}/{service}/${{region}}/${{dt}}",
        MANAGED_TAG[0]: MANAGED_TAG[1],
    }
    if vpc:
        params["skip.header.line.count"] = "1"
        storage = {
            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                          "Parameters": {"field.delim": " ", "serialization.format": " "}},
        }
    else:
        params["classification"] = "cloudtrail"
        storage = {
            "InputFormat": "com.amazon.emr.cloudtrail.CloudTrailInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {"SerializationLibrary": "com.amazon.emr.hive.serde.CloudTrailSerde"},
        }
    storage.update(Location=f"s3://{root}/", Columns=[{"Name": n, "Type": t} for n, t in columns])
    return {"Name": name, "TableType": "EXTERNAL_TABLE", "Parameters": params,
            "PartitionKeys": PARTITIONS, "StorageDescriptor": storage}


def _upsert_table(glue, db, table_input):
    try:
        glue.create_table(DatabaseName=db, TableInput=table_input)
        _say(f"  created table {db}.{table_input['Name']}")
    except glue.exceptions.AlreadyExistsException:
        glue.update_table(DatabaseName=db, TableInput=table_input)
        _say(f"  updated table {db}.{table_input['Name']}")


def cmd_init(a):
    s = load()
    sess = boto3.Session(region_name=s.region)
    account = sess.client("sts").get_caller_identity()["Account"]
    s3, glue, athena = sess.client("s3"), sess.client("glue"), sess.client("athena")
    tags = [{"Key": MANAGED_TAG[0], "Value": MANAGED_TAG[1]}]
    accounts_arg = a.accounts.split(",") if a.accounts else None
    regions_arg = a.regions.split(",") if a.regions else None

    _say(f"Account {account}, Region {s.region}")
    tables = []
    ct_root = _logs_root(a.cloudtrail_bucket, a.cloudtrail_prefix, a.org_id)
    accts, regions = _discover(s3, ct_root, "CloudTrail", accounts_arg, regions_arg)
    if not accts or not regions:
        sys.exit(f"no CloudTrail logs found under s3://{ct_root}/ (check --cloudtrail-prefix / --org-id)")
    _say(f"CloudTrail: s3://{ct_root}/  accounts={','.join(accts)}  regions={','.join(regions)}")
    tables.append(_table_input(s.cloudtrail_table, ct_root, "CloudTrail", accts, regions, CT_COLUMNS))
    if a.vpc_bucket:
        vpc_root = _logs_root(a.vpc_bucket, a.vpc_prefix, a.org_id)
        v_accts, v_regions = _discover(s3, vpc_root, "vpcflowlogs", accounts_arg, regions_arg)
        if v_accts and v_regions:
            _say(f"VPC Flow Logs: s3://{vpc_root}/  accounts={','.join(v_accts)}  regions={','.join(v_regions)}")
            tables.append(_table_input(s.vpc_table, vpc_root, "vpcflowlogs", v_accts, v_regions, VPC_COLUMNS, vpc=True))
        else:
            _say(f"VPC Flow Logs: nothing found under s3://{vpc_root}/, skipping")

    results_bucket = a.results_bucket or f"trailwhisperer-local-results-{account}-{s.region}"
    try:
        kwargs = {"Bucket": results_bucket}
        if s.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": s.region}
        s3.create_bucket(**kwargs)
        s3.put_public_access_block(Bucket=results_bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        s3.put_bucket_lifecycle_configuration(Bucket=results_bucket, LifecycleConfiguration={"Rules": [{
            "ID": "expire-query-results", "Status": "Enabled", "Filter": {"Prefix": ""},
            "Expiration": {"Days": 7}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})
        s3.put_bucket_tagging(Bucket=results_bucket, Tagging={"TagSet": tags})
        _say(f"  created results bucket s3://{results_bucket} (objects expire after 7 days)")
    except s3.exceptions.BucketAlreadyOwnedByYou:
        _say(f"  results bucket s3://{results_bucket} already exists")

    try:
        glue.create_database(DatabaseInput={"Name": s.database, "Description": MANAGED_TAG[1],
                                            "Parameters": {MANAGED_TAG[0]: MANAGED_TAG[1]}})
        _say(f"  created Glue database {s.database}")
    except glue.exceptions.AlreadyExistsException:
        _say(f"  Glue database {s.database} already exists")
    for t in tables:
        _upsert_table(glue, s.database, t)

    cutoff = max(int(a.cutoff_mb * 1024**2), 10 * 1024**2)  # Athena minimum is 10 MB
    wg_config = {
        "ResultConfiguration": {"OutputLocation": f"s3://{results_bucket}/results/"},
        "EnforceWorkGroupConfiguration": True,
        "PublishCloudWatchMetricsEnabled": True,
        "BytesScannedCutoffPerQuery": cutoff,
        "EngineVersion": {"SelectedEngineVersion": "AUTO"},
    }
    try:
        athena.create_work_group(Name=s.workgroup, Configuration=wg_config, Tags=tags,
                                 Description="TrailWhisperer local investigations")
        _say(f"  created Athena workgroup {s.workgroup} (cutoff {cutoff // 1024**2} MB per query)")
    except ClientError as e:
        if "already" not in str(e).lower():
            raise
        athena.update_work_group(WorkGroup=s.workgroup, ConfigurationUpdates={
            "ResultConfigurationUpdates": {"OutputLocation": wg_config["ResultConfiguration"]["OutputLocation"]},
            "EnforceWorkGroupConfiguration": True, "PublishCloudWatchMetricsEnabled": True,
            "BytesScannedCutoffPerQuery": cutoff})
        _say(f"  updated Athena workgroup {s.workgroup} (cutoff {cutoff // 1024**2} MB per query)")

    profile = sess.profile_name if sess.profile_name != "default" else None
    env = f"-e AWS_REGION={s.region}" + (f" -e AWS_PROFILE={profile}" if profile else "")
    _say("\nDone. Add the MCP server to Claude Code:\n")
    print(f"claude mcp add trailwhisperer {env} -- uvx --from "
          f"git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local serve")


def cmd_teardown(a):
    s = load()
    sess = boto3.Session(region_name=s.region)
    account = sess.client("sts").get_caller_identity()["Account"]
    glue, athena, s3 = sess.client("glue"), sess.client("athena"), sess.client("s3")
    try:
        db = glue.get_database(Name=s.database)["Database"]
        if db.get("Parameters", {}).get(MANAGED_TAG[0]) != MANAGED_TAG[1]:
            sys.exit(f"Glue database {s.database} was not created by trailwhisperer-local; refusing to delete")
        for t in (s.cloudtrail_table, s.vpc_table):
            try:
                glue.delete_table(DatabaseName=s.database, Name=t)
                _say(f"  deleted table {s.database}.{t}")
            except glue.exceptions.EntityNotFoundException:
                pass
        glue.delete_database(Name=s.database)
        _say(f"  deleted Glue database {s.database}")
    except glue.exceptions.EntityNotFoundException:
        _say(f"  Glue database {s.database} not found")
    try:
        athena.delete_work_group(WorkGroup=s.workgroup, RecursiveDeleteOption=True)
        _say(f"  deleted Athena workgroup {s.workgroup}")
    except ClientError as e:
        _say(f"  workgroup: {e.response['Error']['Message']}")
    if a.keep_results_bucket:
        return
    bucket = a.results_bucket or f"trailwhisperer-local-results-{account}-{s.region}"
    try:
        tagset = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
    except ClientError:
        _say(f"  results bucket {bucket} not found or not tagged; leaving it")
        return
    if {"Key": MANAGED_TAG[0], "Value": MANAGED_TAG[1]} not in tagset:
        _say(f"  results bucket {bucket} is not managed by trailwhisperer-local; leaving it")
        return
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)
    _say(f"  deleted results bucket s3://{bucket}")


def _glue_tables(sess, s):
    glue, out = sess.client("glue"), {}
    for name in (s.cloudtrail_table, s.vpc_table):
        try:
            out[name] = glue.get_table(DatabaseName=s.database, Name=name)["Table"]
        except glue.exceptions.EntityNotFoundException:
            pass
    return out


def cmd_policy(a):
    s = load()
    sess = boto3.Session(region_name=s.region)
    account = sess.client("sts").get_caller_identity()["Account"]
    wg = sess.client("athena").get_work_group(WorkGroup=s.workgroup)["WorkGroup"]
    results = wg["Configuration"]["ResultConfiguration"]["OutputLocation"].removeprefix("s3://").split("/", 1)[0]
    tables = _glue_tables(sess, s)
    log_buckets = sorted({t["StorageDescriptor"]["Location"].removeprefix("s3://").split("/", 1)[0]
                          for t in tables.values()})
    arn = f"arn:aws:%s:{s.region}:{account}:%s"
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AthenaWorkgroupOnly", "Effect": "Allow",
         "Action": ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults",
                    "athena:StopQueryExecution", "athena:GetWorkGroup"],
         "Resource": arn % ("athena", f"workgroup/{s.workgroup}")},
        {"Sid": "GlueTablesOnly", "Effect": "Allow",
         "Action": ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"],
         "Resource": [arn % ("glue", "catalog"), arn % ("glue", f"database/{s.database}")]
                     + [arn % ("glue", f"table/{s.database}/{t}") for t in tables]},
        {"Sid": "ReadLogs", "Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": [f"arn:aws:s3:::{b}" for b in log_buckets] + [f"arn:aws:s3:::{b}/*" for b in log_buckets]},
        {"Sid": "QueryResults", "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation",
                    "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
         "Resource": [f"arn:aws:s3:::{results}", f"arn:aws:s3:::{results}/*"]},
    ]}
    if a.kms_key_arn:
        policy["Statement"].append({"Sid": "DecryptLogs", "Effect": "Allow", "Action": "kms:Decrypt",
                                    "Resource": a.kms_key_arn})
    print(json.dumps(policy, indent=2))


def cmd_doctor(a):
    s = load()
    sess = boto3.Session(region_name=s.region)
    ok = True

    def check(label, fn):
        nonlocal ok
        try:
            _say(f"  ok    {label}: {fn()}")
        except Exception as e:  # report every failure, keep going
            ok = False
            _say(f"  FAIL  {label}: {e}")

    ident = sess.client("sts").get_caller_identity()
    _say(f"Identity {ident['Arn']}  Region {s.region}")
    tables = _glue_tables(sess, s)

    def glue_tables():
        if not tables:
            raise RuntimeError(f"none found in {s.database}; run init")
        return ", ".join(tables)
    check("Glue tables", glue_tables)

    def wg():
        c = sess.client("athena").get_work_group(WorkGroup=s.workgroup)["WorkGroup"]["Configuration"]
        cutoff = c.get("BytesScannedCutoffPerQuery")
        if not cutoff:
            raise RuntimeError("workgroup has no BytesScannedCutoffPerQuery")
        return f"{s.workgroup}, cutoff {cutoff // 1024**2} MB, enforced={c.get('EnforceWorkGroupConfiguration')}"
    check("Athena workgroup", wg)

    layouts = {n.lower(): est.TableLayout.from_glue(t) for n, t in tables.items()}
    for name in layouts:
        sql = (f"SELECT count(*) FROM {name} WHERE dt >= "
               "date_format(current_timestamp - interval '1' day, '%Y/%m/%d')")

        def one_day(sql=sql):
            e = est.estimate(sql, layouts, est.s3_client(sess))
            if e.bytes is None:
                raise RuntimeError(e.note)
            return f"{e.bytes / 1024**2:.2f} MB in {e.objects} objects across {e.prefixes} prefixes"
        check(f"1-day scan estimate for {name}", one_day)
    sys.exit(0 if ok else 1)


def cmd_serve(a):
    from .server import serve  # imported lazily: the CLI commands don't need the MCP SDK
    serve()


def main(argv=None):
    p = argparse.ArgumentParser(prog="trailwhisperer-local", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="create Glue tables, Athena workgroup and results bucket")
    i.add_argument("--cloudtrail-bucket", required=True)
    i.add_argument("--cloudtrail-prefix", default="", help="key prefix before AWSLogs/, if your trail sets one")
    i.add_argument("--vpc-bucket", help="bucket receiving VPC Flow Logs (optional)")
    i.add_argument("--vpc-prefix", default="")
    i.add_argument("--org-id", help="organization trail: o-xxxxxxxxxx")
    i.add_argument("--accounts", help="comma-separated; default: discovered from the bucket")
    i.add_argument("--regions", help="comma-separated; default: discovered from the bucket")
    i.add_argument("--cutoff-mb", type=float, default=1024, help="Athena per-query scan cutoff (default 1024)")
    i.add_argument("--results-bucket", help="default: trailwhisperer-local-results-<account>-<region>")
    i.set_defaults(fn=cmd_init)

    t = sub.add_parser("teardown", help="delete what init created")
    t.add_argument("--results-bucket")
    t.add_argument("--keep-results-bucket", action="store_true")
    t.set_defaults(fn=cmd_teardown)

    pol = sub.add_parser("policy", help="print a least-privilege IAM policy for the MCP server identity")
    pol.add_argument("--kms-key-arn", help="KMS key encrypting the trail, if any")
    pol.set_defaults(fn=cmd_policy)

    sub.add_parser("doctor", help="check the setup").set_defaults(fn=cmd_doctor)
    sub.add_parser("serve", help="run the MCP server on stdio").set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
