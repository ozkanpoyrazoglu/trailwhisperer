"""TrailWhisperer EC2 deployment stack.

Provisions the same data plane as the serverless CloudFormation template
(`deploy/serverless/investigator-stack.yaml`) — Athena Workgroup, Glue database +
CloudTrail/VPC Flow Log tables (partition projection), Athena results bucket,
DynamoDB chat-sessions table, auth-token secret, least-privilege IAM — but runs
the application on a single EC2 instance via `docker compose` instead of
API Gateway + Lambda + CloudFront.

The instance's UserData installs Docker + Compose, clones the repo, writes the
`.env` (and the SPA's `config.js`) from the stack's own resources, then runs
`docker compose up`. The FastAPI backend is served on :8000 and the static SPA
on :8080; boto3 inside the containers resolves AWS credentials from the
instance role via IMDS (no keys are ever written to disk).
"""
from aws_cdk import (
    Aws,
    CfnOutput,
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
    aws_athena as athena,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_glue as glue,
    aws_iam as iam,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct

# Regions offered to Athena partition projection (mirrors the serverless template).
PROJECTION_REGIONS = (
    "us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1,eu-west-2,eu-central-1,"
    "eu-north-1,ap-south-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,"
    "ap-northeast-2,ca-central-1,sa-east-1"
)

# CloudTrail table columns (kept identical to the serverless Glue table).
CLOUDTRAIL_COLUMNS = [
    ("eventversion", "string"),
    (
        "useridentity",
        "struct<type:string,principalid:string,arn:string,accountid:string,"
        "invokedby:string,accesskeyid:string,username:string,"
        "sessioncontext:struct<attributes:struct<mfaauthenticated:string,"
        "creationdate:string>,sessionissuer:struct<type:string,"
        "principalid:string,arn:string,accountid:string,username:string>>>",
    ),
    ("eventtime", "string"),
    ("eventsource", "string"),
    ("eventname", "string"),
    ("awsregion", "string"),
    ("sourceipaddress", "string"),
    ("useragent", "string"),
    ("errorcode", "string"),
    ("errormessage", "string"),
    ("requestparameters", "string"),
    ("responseelements", "string"),
    ("additionaleventdata", "string"),
    ("requestid", "string"),
    ("eventid", "string"),
    ("resources", "array<struct<arn:string,accountid:string,type:string>>"),
    ("eventtype", "string"),
    ("apiversion", "string"),
    ("readonly", "string"),
    ("recipientaccountid", "string"),
    ("serviceeventdetails", "string"),
    ("sharedeventid", "string"),
    ("vpcendpointid", "string"),
]

# VPC Flow Logs table columns (default fields, space-delimited).
VPC_FLOW_COLUMNS = [
    ("version", "int"),
    ("account_id", "string"),
    ("interface_id", "string"),
    ("srcaddr", "string"),
    ("dstaddr", "string"),
    ("srcport", "int"),
    ("dstport", "int"),
    ("protocol", "bigint"),
    ("packets", "bigint"),
    ("bytes", "bigint"),
    ("start", "bigint"),
    ("end", "bigint"),
    ("action", "string"),
    ("log_status", "string"),
]

PARTITION_KEYS = [
    glue.CfnTable.ColumnProperty(name="account", type="string"),
    glue.CfnTable.ColumnProperty(name="region", type="string"),
    glue.CfnTable.ColumnProperty(name="dt", type="string"),
]


def _projection_params(dt_path_var: str) -> dict:
    """Common partition-projection parameters shared by the log tables."""
    return {
        "projection.enabled": "true",
        "projection.account.type": "enum",
        "projection.account.values": Aws.ACCOUNT_ID,
        "projection.region.type": "enum",
        "projection.region.values": PROJECTION_REGIONS,
        "projection.dt.type": "date",
        "projection.dt.format": "yyyy/MM/dd",
        "projection.dt.range": "NOW-3YEARS,NOW",
        "projection.dt.interval": "1",
        "projection.dt.interval.unit": "DAYS",
    }


class TrailWhispererEc2Stack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ------------------------------------------------------------------ #
        # Parameters (mirror the serverless template, plus EC2-specific ones) #
        # ------------------------------------------------------------------ #
        p_ct_bucket = CfnParameter(
            self, "CloudTrailLogBucketName", type="String",
            description="Existing S3 bucket that receives CloudTrail management events.",
        )
        p_vpc_bucket = CfnParameter(
            self, "VpcFlowLogsBucketName", type="String",
            description="Existing S3 bucket that receives VPC Flow Logs (default fields).",
        )
        p_db = CfnParameter(self, "GlueDatabaseName", type="String", default="trailwhisperer_db")
        p_table = CfnParameter(self, "GlueTableName", type="String", default="cloudtrail_logs")
        p_vpc_table = CfnParameter(self, "VpcFlowLogsTableName", type="String", default="vpc_flow_logs")
        p_model = CfnParameter(
            self, "BedrockModelId", type="String", default="global.anthropic.claude-sonnet-4-6",
            description="Bedrock model id (or inference profile) for NL->SQL and summarization.",
        )
        p_cutoff = CfnParameter(
            self, "BytesScannedCutoff", type="Number", default=1073741824,
            description="Per-query bytes-scanned cap (runaway-cost guard). Default 1 GB.",
        )
        p_max_days = CfnParameter(
            self, "AllowedTimeRangeMaxDays", type="Number", default=90,
            description="Max eventTime window (days) the orchestrator allows per query.",
        )
        p_instance_type = CfnParameter(
            self, "InstanceType", type="String", default="t3.small",
            description="EC2 instance type for the app VM.",
        )
        p_repo_url = CfnParameter(
            self, "RepoUrl", type="String",
            default="https://github.com/ozkanpoyrazoglu/trailwhisperer.git",
            description="Git URL the instance clones the app from (must be reachable/public).",
        )
        p_repo_branch = CfnParameter(
            self, "RepoBranch", type="String", default="main",
            description="Git branch to check out on the instance.",
        )
        p_ingress_cidr = CfnParameter(
            self, "AllowedIngressCidr", type="String", default="0.0.0.0/0",
            description="CIDR allowed to reach the app (ports 8080/8000). "
            "Lock this to your IP; the default is open to the internet.",
        )

        # ------------------------------------------------------------------ #
        # Data plane: results bucket, sessions table, auth secret            #
        # ------------------------------------------------------------------ #
        results_bucket = s3.Bucket(
            self, "AthenaResultsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=[s3.LifecycleRule(id="ExpireResults", expiration=Duration.days(7))],
            # Ephemeral by design: tear the stack down and the results go with it.
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        sessions_table = dynamodb.Table(
            self, "ChatSessionsTable",
            partition_key=dynamodb.Attribute(name="session_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,
        )

        auth_secret = secretsmanager.Secret(
            self, "AuthTokenSecret",
            description="Bearer token the SPA sends to the orchestrator API.",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{}',
                generate_string_key="token",
                password_length=40,
                exclude_punctuation=True,
            ),
        )

        # ------------------------------------------------------------------ #
        # Glue catalog: database + CloudTrail + VPC Flow Logs tables          #
        # ------------------------------------------------------------------ #
        glue_db = glue.CfnDatabase(
            self, "GlueDatabase",
            catalog_id=Aws.ACCOUNT_ID,
            database_input=glue.CfnDatabase.DatabaseInputProperty(name=p_db.value_as_string),
        )

        ct_params = _projection_params("dt")
        ct_params["classification"] = "cloudtrail"
        ct_params["storage.location.template"] = (
            f"s3://{p_ct_bucket.value_as_string}/AWSLogs/${{account}}/CloudTrail/${{region}}/${{dt}}"
        )
        ct_table = glue.CfnTable(
            self, "GlueTable",
            catalog_id=Aws.ACCOUNT_ID,
            database_name=p_db.value_as_string,
            table_input=glue.CfnTable.TableInputProperty(
                name=p_table.value_as_string,
                table_type="EXTERNAL_TABLE",
                parameters=ct_params,
                partition_keys=PARTITION_KEYS,
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{p_ct_bucket.value_as_string}/AWSLogs/",
                    input_format="com.amazon.emr.cloudtrail.CloudTrailInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="com.amazon.emr.hive.serde.CloudTrailSerde",
                    ),
                    columns=[glue.CfnTable.ColumnProperty(name=n, type=t) for n, t in CLOUDTRAIL_COLUMNS],
                ),
            ),
        )
        ct_table.node.add_dependency(glue_db)

        vpc_params = _projection_params("dt")
        vpc_params["skip.header.line.count"] = "1"
        vpc_params["storage.location.template"] = (
            f"s3://{p_vpc_bucket.value_as_string}/AWSLogs/${{account}}/vpcflowlogs/${{region}}/${{dt}}"
        )
        vpc_table = glue.CfnTable(
            self, "VpcFlowLogsTable",
            catalog_id=Aws.ACCOUNT_ID,
            database_name=p_db.value_as_string,
            table_input=glue.CfnTable.TableInputProperty(
                name=p_vpc_table.value_as_string,
                table_type="EXTERNAL_TABLE",
                parameters=vpc_params,
                partition_keys=PARTITION_KEYS,
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{p_vpc_bucket.value_as_string}/AWSLogs/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                        parameters={"field.delim": " ", "serialization.format": " "},
                    ),
                    columns=[glue.CfnTable.ColumnProperty(name=n, type=t) for n, t in VPC_FLOW_COLUMNS],
                ),
            ),
        )
        vpc_table.node.add_dependency(glue_db)

        # ------------------------------------------------------------------ #
        # Athena workgroup (bytes-scanned cutoff + enforced results location) #
        # ------------------------------------------------------------------ #
        workgroup = athena.CfnWorkGroup(
            self, "InvestigatorWorkGroup",
            name=f"{Aws.STACK_NAME}-wg",
            state="ENABLED",
            recursive_delete_option=True,
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                enforce_work_group_configuration=True,
                bytes_scanned_cutoff_per_query=p_cutoff.value_as_number,
                publish_cloud_watch_metrics_enabled=True,
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{results_bucket.bucket_name}/results/",
                ),
            ),
        )

        # ------------------------------------------------------------------ #
        # Networking: public-subnet VPC, no NAT (keeps the no-NAT constraint) #
        # ------------------------------------------------------------------ #
        vpc = ec2.Vpc(
            self, "Vpc",
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24,
                ),
            ],
        )

        sg = ec2.SecurityGroup(
            self, "AppSecurityGroup",
            vpc=vpc,
            description="TrailWhisperer app VM - SPA (8080) + API (8000).",
            allow_all_outbound=True,
        )
        sg.add_ingress_rule(
            ec2.Peer.ipv4(p_ingress_cidr.value_as_string), ec2.Port.tcp(8080), "SPA (frontend)",
        )
        sg.add_ingress_rule(
            ec2.Peer.ipv4(p_ingress_cidr.value_as_string), ec2.Port.tcp(8000), "API (backend)",
        )

        # ------------------------------------------------------------------ #
        # Least-privilege instance role (mirrors the Lambda orchestrator role)#
        # ------------------------------------------------------------------ #
        role = iam.Role(
            self, "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="TrailWhisperer EC2 app role - Bedrock/Athena/Glue/S3 least privilege.",
            managed_policies=[
                # SSM Session Manager access so you can shell in without an SSH key.
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            ],
        )
        role.add_to_policy(iam.PolicyStatement(
            sid="Bedrock",
            actions=["bedrock:InvokeModel"],
            resources=[
                f"arn:aws:bedrock:{Aws.REGION}::foundation-model/{p_model.value_as_string}",
                f"arn:aws:bedrock:{Aws.REGION}:{Aws.ACCOUNT_ID}:inference-profile/*",
                "arn:aws:bedrock:*::foundation-model/*",
            ],
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="Athena",
            actions=[
                "athena:StartQueryExecution", "athena:GetQueryExecution",
                "athena:GetQueryResults", "athena:StopQueryExecution",
            ],
            resources=[f"arn:aws:athena:{Aws.REGION}:{Aws.ACCOUNT_ID}:workgroup/{workgroup.name}"],
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="Glue",
            actions=["glue:GetTable", "glue:GetPartitions", "glue:GetDatabase"],
            resources=[
                f"arn:aws:glue:{Aws.REGION}:{Aws.ACCOUNT_ID}:catalog",
                f"arn:aws:glue:{Aws.REGION}:{Aws.ACCOUNT_ID}:database/{p_db.value_as_string}",
                f"arn:aws:glue:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{p_db.value_as_string}/{p_table.value_as_string}",
                f"arn:aws:glue:{Aws.REGION}:{Aws.ACCOUNT_ID}:table/{p_db.value_as_string}/{p_vpc_table.value_as_string}",
            ],
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="SourceLogsReadOnly",
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=[
                f"arn:aws:s3:::{p_ct_bucket.value_as_string}",
                f"arn:aws:s3:::{p_ct_bucket.value_as_string}/*",
                f"arn:aws:s3:::{p_vpc_bucket.value_as_string}",
                f"arn:aws:s3:::{p_vpc_bucket.value_as_string}/*",
            ],
        ))
        # Athena results bucket read/write.
        results_bucket.grant_read_write(role)
        # Auth token secret + chat sessions table.
        auth_secret.grant_read(role)
        sessions_table.grant_read_write_data(role)

        # ------------------------------------------------------------------ #
        # EC2 instance + UserData (install Docker, write .env, compose up)     #
        # ------------------------------------------------------------------ #
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "set -euxo pipefail",
            "dnf update -y",
            "dnf install -y docker git jq",
            "systemctl enable --now docker",
            # Install the Docker Compose v2 CLI plugin (AL2023 has no compose package).
            "mkdir -p /usr/libexec/docker/cli-plugins",
            "ARCH=$(uname -m)",
            'curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-${ARCH}"'
            " -o /usr/libexec/docker/cli-plugins/docker-compose",
            "chmod +x /usr/libexec/docker/cli-plugins/docker-compose",
            # Clone the application.
            f'git clone --depth 1 --branch "{p_repo_branch.value_as_string}" '
            f'"{p_repo_url.value_as_string}" /opt/trailwhisperer',
            "cd /opt/trailwhisperer",
            # Fetch the auth token and this instance's public IP (IMDSv2).
            f'REGION="{Aws.REGION}"',
            f'TOKEN=$(aws secretsmanager get-secret-value --secret-id "{auth_secret.secret_arn}"'
            ' --query SecretString --output text --region "$REGION" | jq -r .token)',
            'IMDS=$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token"'
            ' -H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
            'PUBLIC_IP=$(curl -fsSL -H "X-aws-ec2-metadata-token: $IMDS"'
            ' http://169.254.169.254/latest/meta-data/public-ipv4)',
            # Write .env. No AWS keys: boto3 uses the instance role via IMDS.
            # ATHENA_OUTPUT_LOCATION stays unset — the workgroup enforces its own.
            "cat > .env <<EOF",
            "AWS_REGION=$REGION",
            f"GLUE_DATABASE={p_db.value_as_string}",
            f"GLUE_TABLE={p_table.value_as_string}",
            f"GLUE_VPC_TABLE={p_vpc_table.value_as_string}",
            f"ATHENA_WORKGROUP={workgroup.name}",
            f"BEDROCK_MODEL_ID={p_model.value_as_string}",
            f"BYTES_SCANNED_CUTOFF={p_cutoff.value_as_string}",
            f"ALLOWED_TIME_RANGE_MAX_DAYS={p_max_days.value_as_string}",
            "AUTH_TOKEN=$TOKEN",
            f"DYNAMODB_SESSION_TABLE={sessions_table.table_name}",
            "ALLOWED_ORIGIN=http://$PUBLIC_IP:8080",
            "EOF",
            # Point the SPA at this instance's backend.
            "cat > frontend/config.js <<EOF",
            'window.TRAILWHISPERER_CONFIG = { apiBase: "http://'"$PUBLIC_IP"':8000" };',
            "EOF",
            # Bring the stack up (build backend image + serve frontend). Pass only
            # the base compose file so the local-dev override (Uvicorn --reload) is
            # NOT applied on this always-on VM — the backend runs the production CMD.
            "docker compose -f docker-compose.yml up -d --build",
        )

        instance = ec2.Instance(
            self, "AppInstance",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(p_instance_type.value_as_string),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            security_group=sg,
            role=role,
            user_data=user_data,
            require_imdsv2=True,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(20, encrypted=True),
                ),
            ],
        )
        # Docker containers on the default bridge need one extra metadata hop to
        # reach IMDSv2 for the instance-role credentials.
        instance.instance.add_property_override("MetadataOptions.HttpTokens", "required")
        instance.instance.add_property_override("MetadataOptions.HttpPutResponseHopLimit", 2)

        # ------------------------------------------------------------------ #
        # Outputs                                                             #
        # ------------------------------------------------------------------ #
        CfnOutput(self, "UiUrl", value=f"http://{instance.instance_public_ip}:8080",
                  description="Open this in your browser (allow a few minutes for first boot).")
        CfnOutput(self, "ApiUrl", value=f"http://{instance.instance_public_ip}:8000")
        CfnOutput(self, "InstanceId", value=instance.instance_id)
        CfnOutput(self, "AuthSecretArn", value=auth_secret.secret_arn,
                  description="Read the login token: aws secretsmanager get-secret-value --secret-id <this>.")
        CfnOutput(self, "AthenaWorkGroupName", value=workgroup.name)
