"""
AWS IAM Identity Center Data Transform and Load Lambda Function.

Transforms extracted data into CSV reports and uploads to S3.
"""

import os
import logging
import csv
from datetime import date, timezone, datetime
from typing import Any

import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
PERMISSION_TABLE = os.environ['PERMISSION_TABLE_NAME']
USER_TABLE = os.environ['USER_TABLE_NAME']
SNS_ARN = os.environ['TOPIC_ARN']
BUCKET_NAME = os.environ['BUCKET_NAME']

# Constants
EXCEL_CHAR_LIMIT = 32700
CSV_HEADERS = [
    'User', 'PrincipalId', 'PrincipalType', 'GroupName',
    'AccountIdAssignment', 'PermissionSetARN', 'PermissionSetName',
    'InlinePolicy', 'CustomerManagedPolicy', 'AWSManagedPolicy',
    'PermissionBoundary'
]

# Initialize clients outside handler for connection reuse
ddb = boto3.resource('dynamodb')
sns = boto3.client('sns')
s3 = boto3.client('s3')


def scan_table(table) -> list[dict]:
    """Scan entire DynamoDB table with pagination."""
    items = []
    response = table.scan()
    items.extend(response.get('Items', []))
    
    while response.get('LastEvaluatedKey'):
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        items.extend(response.get('Items', []))
    
    return items


def query_permissions(table, instance_arn: str, principal_id: str) -> list[dict]:
    """Query permissions for a principal with pagination."""
    items = []
    params = {
        'KeyConditionExpression': 'id = :id',
        'FilterExpression': 'contains(principalId, :pid)',
        'ExpressionAttributeValues': {':id': instance_arn, ':pid': principal_id}
    }
    
    response = table.query(**params)
    items.extend(response.get('Items', []))
    
    while response.get('LastEvaluatedKey'):
        params['ExclusiveStartKey'] = response['LastEvaluatedKey']
        response = table.query(**params)
        items.extend(response.get('Items', []))
    
    return items


def truncate_for_excel(value: Any) -> Any:
    """Truncate value if it exceeds Excel character limit."""
    str_val = str(value)
    if len(str_val) > EXCEL_CHAR_LIMIT:
        return 'Content exceeds Excel limit - see AWS Console'
    return value


def write_user_permissions(
    writer: csv.writer,
    user_name: str,
    principal_id: str,
    group_name: str,
    permissions_table,
    instance_arn: str
) -> int:
    """Write permission rows for a user/group. Returns row count."""
    permissions = query_permissions(permissions_table, instance_arn, principal_id)
    rows_written = 0
    
    if not permissions:
        writer.writerow([
            user_name, principal_id, 'USER', group_name,
            'not_assigned', '', '', '', '', '', ''
        ])
        return 1
    
    for perm in permissions:
        managed_arns = [p['policyArn'] for p in perm.get('managedPolicies', [])]
        
        for idx, account_id in enumerate(perm.get('accountId', [])):
            if principal_id == perm['principalId'][idx]:
                writer.writerow([
                    user_name,
                    principal_id,
                    perm['principalType'][idx],
                    group_name,
                    account_id,
                    perm['permissionSetArn'],
                    perm['permissionSetName'],
                    truncate_for_excel(perm.get('inlinePolicies', '')),
                    truncate_for_excel(perm.get('customerPolicies', [])),
                    truncate_for_excel(managed_arns),
                    perm.get('permissionsBoundary', '')
                ])
                rows_written += 1
    
    return rows_written


def generate_report(users: list[dict], permissions_table, instance_arn: str, local_path: str) -> int:
    """Generate CSV report file. Returns total row count."""
    total_rows = 0
    
    with open(local_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        
        for user in users:
            user_id = user['userId']
            user_name = user['userName']
            
            # Individual user assignments
            total_rows += write_user_permissions(
                writer, user_name, user_id, '',
                permissions_table, instance_arn
            )
            
            # Group assignments
            group_ids = user.get('groupIds', [])
            group_names = user.get('groupName', [])
            
            for idx, group_id in enumerate(group_ids):
                gname = group_names[idx] if idx < len(group_names) else 'Unknown'
                total_rows += write_user_permissions(
                    writer, user_name, group_id, gname,
                    permissions_table, instance_arn
                )
    
    return total_rows


def send_notification(s3_key: str, row_count: int) -> None:
    """Send SNS notification about completed report."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    message = f"""IAM Identity Center Permission Analysis Complete

Report Details:
- S3 Location: s3://{BUCKET_NAME}/{s3_key}
- Total Records: {row_count}
- Generated: {timestamp}

Download the report from S3 to review user permissions and policy assignments.
"""
    
    sns.publish(
        TopicArn=SNS_ARN,
        Subject='IAM Identity Center Analyzer - Report Ready',
        Message=message
    )


def handler(event: dict, context) -> dict:
    """Lambda handler for data transformation and loading."""
    logger.info("Starting data transform and load")
    
    # Handle Step Functions payload wrapper
    payload = event.get('Payload', event)
    if isinstance(payload, dict) and 'Payload' in payload:
        payload = payload['Payload']
    
    instance_arn = payload['instanceArn']
    
    # Generate file paths
    report_date = date.today().strftime('%Y%m%d')
    s3_key = f"reports/{report_date}_identity_center_analysis.csv"
    local_path = f"/tmp/{report_date}_report.csv"
    
    # Get table references
    permissions_table = ddb.Table(PERMISSION_TABLE)
    users_table = ddb.Table(USER_TABLE)
    
    # Scan users
    users = scan_table(users_table)
    logger.info("Processing %d users", len(users))
    
    # Generate report
    row_count = generate_report(users, permissions_table, instance_arn, local_path)
    logger.info("Generated report with %d rows", row_count)
    
    # Upload to S3
    s3.upload_file(
        local_path,
        BUCKET_NAME,
        s3_key,
        ExtraArgs={'ServerSideEncryption': 'aws:kms'}
    )
    logger.info("Uploaded report to s3://%s/%s", BUCKET_NAME, s3_key)
    
    # Send notification
    send_notification(s3_key, row_count)
    
    logger.info("Transform and load complete")
    
    return {
        'status': 'success',
        'report': {
            'bucket': BUCKET_NAME,
            'key': s3_key,
            'rowCount': row_count
        }
    }
