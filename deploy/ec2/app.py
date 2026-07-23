#!/usr/bin/env python3
"""CDK entry point for the TrailWhisperer EC2 (always-on VM) deployment.

This is the *alternative* to the serverless CloudFormation stack in
`deploy/serverless/`. It provisions the same background data plane (Athena
Workgroup, Glue tables, results bucket, DynamoDB sessions table, least-privilege
IAM, auth-token secret) plus a single EC2 instance that runs the app via
`docker compose` instead of API Gateway + Lambda + CloudFront.

Unlike the serverless stack, this instance is always-on, so it is NOT zero-idle
cost — see deploy/README.md for the trade-offs.
"""
import aws_cdk as cdk

from trailwhisperer_ec2.stack import TrailWhispererEc2Stack

app = cdk.App()

TrailWhispererEc2Stack(
    app,
    "TrailWhispererEc2Stack",
    # Resolve account/region from the CLI environment so VPC AZ lookups work.
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
    description="TrailWhisperer EC2 deployment: Athena/Glue/S3 data plane + a "
    "Docker-compose VM running the FastAPI backend and static SPA.",
)

app.synth()
