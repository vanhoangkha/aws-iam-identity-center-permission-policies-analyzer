# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Security Features

This project implements AWS security best practices:

- **Encryption at Rest**: All data encrypted using AWS KMS
  - DynamoDB tables
  - S3 buckets
  - SNS topics
  - SQS queues (DLQ)
  - CloudWatch Logs

- **Encryption in Transit**: HTTPS enforced via S3 bucket policy

- **Access Control**:
  - Least privilege IAM policies
  - S3 Block Public Access
  - DynamoDB deletion protection

- **Data Protection**:
  - DynamoDB Point-in-Time Recovery
  - S3 versioning
  - Automatic data cleanup via TTL

- **Resilience**:
  - Dead Letter Queues for failed Lambda invocations
  - Step Functions retry with exponential backoff

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue.

## Security Updates

Security updates are released as patch versions (e.g., 2.0.1) and announced via GitHub releases.
