"""
AWS IAM Identity Center Data Extraction Lambda Function.

Extracts permission sets, policies, and user data from IAM Identity Center
and stores in DynamoDB for analysis.
"""

import json
import os
import logging
import time
from typing import Any

import boto3
import botocore.exceptions

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
PERMISSION_TABLE = os.environ['PERMISSION_TABLE_NAME']
USER_TABLE = os.environ['USER_TABLE_NAME']

# Constants
TTL_DAYS = 90
SECONDS_PER_DAY = 86400

# Initialize clients outside handler for connection reuse
ddb = boto3.resource('dynamodb')
iam = boto3.client('iam')


class ValidationError(Exception):
    """Raised when event validation fails."""


def validate_event(event: dict) -> None:
    """Validate required event parameters."""
    required = ['identityStoreId', 'instanceArn', 'ssoDeployedRegion']
    missing = [k for k in required if not event.get(k)]
    if missing:
        raise ValidationError(f"Missing required parameters: {missing}")


def paginate(client_method, result_key: str, **kwargs) -> list:
    """Generic paginator for AWS API calls with NextToken."""
    results = []
    response = client_method(**kwargs)
    results.extend(response.get(result_key, []))
    
    while response.get('NextToken'):
        kwargs['NextToken'] = response['NextToken']
        response = client_method(**kwargs)
        results.extend(response.get(result_key, []))
    
    return results


def get_ttl() -> int:
    """Calculate TTL timestamp."""
    return int(time.time()) + (TTL_DAYS * SECONDS_PER_DAY)


def get_managed_policies(sso_client, instance_arn: str, ps_arn: str) -> list[dict]:
    """Retrieve managed policies with full policy documents."""
    policies = paginate(
        sso_client.list_managed_policies_in_permission_set,
        'AttachedManagedPolicies',
        InstanceArn=instance_arn,
        PermissionSetArn=ps_arn
    )
    
    result = []
    for policy in policies:
        policy_data = {'policyArn': policy['Arn'], 'policyType': 'aws_managed', 'policyJson': ''}
        try:
            details = iam.get_policy(PolicyArn=policy['Arn'])
            version_id = details['Policy']['DefaultVersionId']
            doc = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=version_id)
            policy_data['policyJson'] = json.dumps(doc['PolicyVersion']['Document'])
        except botocore.exceptions.ClientError as e:
            logger.warning("Failed to get policy %s: %s", policy['Arn'], e)
        result.append(policy_data)
    
    return result


def get_customer_policies(sso_client, instance_arn: str, ps_arn: str) -> list:
    """Retrieve customer managed policy references."""
    return paginate(
        sso_client.list_customer_managed_policy_references_in_permission_set,
        'CustomerManagedPolicyReferences',
        InstanceArn=instance_arn,
        PermissionSetArn=ps_arn
    )


def get_permission_boundary(sso_client, instance_arn: str, ps_arn: str) -> Any:
    """Retrieve permission boundary if exists."""
    try:
        resp = sso_client.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        return resp['PermissionsBoundary']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return ''
        raise


def process_permission_sets(sso_client, instance_arn: str, table) -> int:
    """Process all permission sets and store in DynamoDB."""
    try:
        permission_sets = paginate(
            sso_client.list_permission_sets,
            'PermissionSets',
            InstanceArn=instance_arn
        )
    except botocore.exceptions.ClientError as e:
        if 'ValidationException' in str(e) or 'not supported' in str(e):
            logger.warning("Permission sets not supported for this instance type")
            return 0
        raise
    
    logger.info("Processing %d permission sets", len(permission_sets))
    
    for ps_arn in permission_sets:
        logger.debug("Processing permission set: %s", ps_arn)
        
        # Get accounts and assignments
        accounts = paginate(
            sso_client.list_accounts_for_provisioned_permission_set,
            'AccountIds',
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        
        ps_details = sso_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        
        principal_ids, account_ids, principal_types = [], [], []
        
        for account in accounts:
            assignments = paginate(
                sso_client.list_account_assignments,
                'AccountAssignments',
                InstanceArn=instance_arn,
                AccountId=account,
                PermissionSetArn=ps_arn
            )
            for a in assignments:
                principal_ids.append(a['PrincipalId'])
                account_ids.append(a['AccountId'])
                principal_types.append(a['PrincipalType'])
        
        # Get inline policy
        inline_resp = sso_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        
        # Store in DynamoDB
        table.put_item(Item={
            'id': instance_arn,
            'permissionSetArn': ps_arn,
            'permissionSetName': ps_details['PermissionSet']['Name'],
            'principalId': principal_ids,
            'accountId': account_ids,
            'principalType': principal_types,
            'managedPolicies': get_managed_policies(sso_client, instance_arn, ps_arn),
            'inlinePolicies': inline_resp.get('InlinePolicy', ''),
            'customerPolicies': get_customer_policies(sso_client, instance_arn, ps_arn),
            'permissionsBoundary': get_permission_boundary(sso_client, instance_arn, ps_arn),
            'ttl': get_ttl()
        })
    
    return len(permission_sets)


def process_users(identity_client, identity_store_id: str, table) -> int:
    """Process all users and their group memberships."""
    users = paginate(
        identity_client.list_users,
        'Users',
        IdentityStoreId=identity_store_id
    )
    
    logger.info("Processing %d users", len(users))
    
    for user in users:
        memberships = paginate(
            identity_client.list_group_memberships_for_member,
            'GroupMemberships',
            IdentityStoreId=identity_store_id,
            MemberId={'UserId': user['UserId']}
        )
        
        group_ids = []
        group_names = []
        for m in memberships:
            group_ids.append(m['GroupId'])
            try:
                group = identity_client.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=m['GroupId']
                )
                group_names.append(group['DisplayName'])
            except botocore.exceptions.ClientError as e:
                logger.warning("Failed to describe group %s: %s", m['GroupId'], e)
                group_names.append('Unknown')
        
        table.put_item(Item={
            'userId': user['UserId'],
            'userName': user['UserName'],
            'groupIds': group_ids,
            'groupName': group_names,
            'ttl': get_ttl()
        })
    
    return len(users)


def handler(event: dict, context) -> dict:
    """Lambda handler for data extraction."""
    logger.info("Starting data extraction")
    
    try:
        validate_event(event)
    except ValidationError as e:
        logger.error("Validation failed: %s", e)
        raise
    
    identity_store_id = event['identityStoreId']
    instance_arn = event['instanceArn']
    sso_region = event['ssoDeployedRegion']
    
    # Initialize regional clients
    sso = boto3.client('sso-admin', region_name=sso_region)
    identitystore = boto3.client('identitystore', region_name=sso_region)
    
    # Get table references
    permissions_table = ddb.Table(PERMISSION_TABLE)
    users_table = ddb.Table(USER_TABLE)
    
    # Process data
    ps_count = process_permission_sets(sso, instance_arn, permissions_table)
    user_count = process_users(identitystore, identity_store_id, users_table)
    
    logger.info("Extraction complete: %d permission sets, %d users", ps_count, user_count)
    
    return {
        **event,
        'extractionStats': {
            'permissionSets': ps_count,
            'users': user_count
        }
    }
