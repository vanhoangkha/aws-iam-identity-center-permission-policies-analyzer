#!/usr/bin/env python3
"""Generate architecture diagram for IAM Identity Center Analyzer."""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.database import Dynamodb
from diagrams.aws.integration import Eventbridge, StepFunctions, SNS, SQS
from diagrams.aws.storage import S3
from diagrams.aws.security import KMS, IdentityAndAccessManagementIam
from diagrams.aws.management import Cloudwatch

with Diagram(
    "IAM Identity Center Permission Policies Analyzer",
    filename="docs/architecture",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "14", "bgcolor": "white"}
):
    
    # Trigger
    schedule = Eventbridge("EventBridge\nScheduler\n(Monthly)")
    
    # Orchestration
    with Cluster("Orchestration"):
        sfn = StepFunctions("Step Functions\nWorkflow")
    
    # Processing
    with Cluster("Processing"):
        extract = Lambda("Data\nExtraction")
        transform = Lambda("Transform\n& Load")
        dlq1 = SQS("DLQ")
        dlq2 = SQS("DLQ")
    
    # Storage
    with Cluster("Storage"):
        permissions_db = Dynamodb("Permission\nSets")
        users_db = Dynamodb("Users")
        reports = S3("Reports\nBucket")
        logs_bucket = S3("Access\nLogs")
    
    # Security & Notifications
    with Cluster("Security"):
        kms = KMS("KMS Key")
        iam = IdentityAndAccessManagementIam("IAM\nIdentity Center")
    
    notify = SNS("SNS\nNotifications")
    logs = Cloudwatch("CloudWatch\nLogs")
    
    # Connections
    schedule >> sfn
    sfn >> extract
    extract >> dlq1
    extract >> permissions_db
    extract >> users_db
    extract >> iam
    
    sfn >> transform
    transform >> dlq2
    transform >> permissions_db
    transform >> users_db
    transform >> reports
    transform >> notify
    
    reports >> logs_bucket
    
    # KMS encrypts everything
    kms >> Edge(style="dashed") >> permissions_db
    kms >> Edge(style="dashed") >> users_db
    kms >> Edge(style="dashed") >> reports
    kms >> Edge(style="dashed") >> notify
    
    # Logging
    extract >> Edge(style="dotted") >> logs
    transform >> Edge(style="dotted") >> logs
    sfn >> Edge(style="dotted") >> logs
