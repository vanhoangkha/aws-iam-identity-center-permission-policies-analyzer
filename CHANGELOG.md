# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-02

### Added
- KMS encryption for all services (DynamoDB, S3, SNS, SQS, CloudWatch Logs)
- S3 access logging bucket
- DynamoDB Point-in-Time Recovery (PITR)
- DynamoDB deletion protection
- Dead Letter Queues for Lambda functions
- Step Functions retry/catch with failure notifications
- Unit tests (21 tests covering both Lambda functions)
- Type hints and docstrings in Python code
- Input validation for Lambda handlers
- Support for account-level Identity Center instances
- Resource tagging for all resources
- CloudFormation outputs for key resources

### Changed
- Upgraded Python runtime from 3.9 to 3.12
- Switched to ARM64 architecture for cost optimization
- Replaced broad IAM policies with least privilege
- Improved pagination handling for all AWS API calls
- Restructured code with helper functions
- Enhanced error handling and logging
- Updated S3 key format to `reports/YYYYMMDD_identity_center_analysis.csv`

### Fixed
- DynamoDB serialization error with group memberships
- KMS permissions for Step Functions SNS publishing
- Typo: `policryArn` → `policyArn`

### Removed
- Static images (moved to text-based architecture diagram)
- Unused DynamoDB streams (kept for future use)
- Broad AWS managed policies (IAMReadOnlyAccess, AWSSSOReadOnly)

### Security
- All data encrypted at rest with KMS
- S3 bucket policy enforces HTTPS and KMS encryption
- S3 Block Public Access enabled
- CloudWatch Logs encrypted with KMS
- Least privilege IAM policies

## [1.0.0] - 2023-xx-xx

### Added
- Initial release by AWS Samples
- Monthly scheduled analysis of Identity Center users
- CSV report generation
- SNS email notifications
