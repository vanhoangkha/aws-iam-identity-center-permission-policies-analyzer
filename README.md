# AWS IAM Identity Center Permission Policies Analyzer

Automated analysis of IAM Identity Center users and their permission policies (Inline, AWS Managed, Customer Managed).

## Architecture

```
EventBridge Schedule (monthly)
         │
         ▼
   Step Functions
         │
         ├──► Lambda: Data Extraction ──► DynamoDB (permissions, users)
         │
         └──► Lambda: Transform/Load ──► S3 (CSV report) + SNS (notification)
```

## Prerequisites

- AWS IAM Identity Center instance configured
- Identity Store ID (e.g., `d-xxxxxxxxxx`)
- Instance ARN (e.g., `arn:aws:sso:::instance/ssoins-xxxxxxxxxx`)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)

## Deployment

```bash
sam build
sam deploy --guided
```

Parameters:
- **Stack Name**: Max 34 chars, lowercase
- **EmailAddress**: For SNS notifications
- **IdentityStoreID**: Your Identity Store ID
- **IdentityStoreInstanceArn**: Your SSO Instance ARN
- **ReportRetentionDays**: Days to keep reports (default: 365)
- **Environment**: dev/staging/prod

## Manual Execution

In Step Functions console, start execution with:

```json
{
  "identityStoreId": "d-xxxxxxxxxx",
  "instanceArn": "arn:aws:sso:::instance/ssoins-xxxxxxxxxx",
  "ssoDeployedRegion": "us-east-1"
}
```

## Report Output

CSV report with columns:
- User, PrincipalId, PrincipalType, GroupName
- AccountIdAssignment, PermissionSetARN, PermissionSetName
- InlinePolicy, CustomerManagedPolicy, AWSManagedPolicy, PermissionBoundary

## Schedule

Default: 1st day of each month at 08:00 UTC

Update in EventBridge Scheduler console if needed.

## Cleanup

```bash
# Empty S3 buckets first
aws s3 rm s3://<stack-name>-reports-<account-id> --recursive
aws s3 rm s3://<stack-name>-access-logs-<account-id> --recursive

# Delete stack
sam delete
```

## Security Features

- KMS encryption (DynamoDB, S3, SNS, SQS, CloudWatch Logs)
- S3 access logging
- HTTPS-only S3 bucket policy
- DynamoDB Point-in-Time Recovery
- Dead Letter Queues
- X-Ray tracing
- Least privilege IAM policies

## License

MIT-0
