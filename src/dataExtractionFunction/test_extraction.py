"""Unit tests for data extraction function."""

import pytest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock environment variables before importing handler
os.environ['PERMISSION_TABLE_NAME'] = 'test-permissions'
os.environ['USER_TABLE_NAME'] = 'test-users'
os.environ['LOG_LEVEL'] = 'DEBUG'


class TestValidation:
    def test_validate_event_success(self):
        from handler import validate_event
        event = {
            'identityStoreId': 'd-1234567890',
            'instanceArn': 'arn:aws:sso:::instance/ssoins-123',
            'ssoDeployedRegion': 'us-east-1'
        }
        validate_event(event)  # Should not raise

    def test_validate_event_missing_keys(self):
        from handler import validate_event, ValidationError
        event = {'identityStoreId': 'd-123'}
        with pytest.raises(ValidationError) as exc:
            validate_event(event)
        assert 'instanceArn' in str(exc.value)


class TestPagination:
    def test_paginate_single_page(self):
        from handler import paginate
        mock_method = MagicMock(return_value={'Items': [1, 2, 3]})
        result = paginate(mock_method, 'Items', Param='value')
        assert result == [1, 2, 3]
        mock_method.assert_called_once()

    def test_paginate_multiple_pages(self):
        from handler import paginate
        mock_method = MagicMock(side_effect=[
            {'Items': [1, 2], 'NextToken': 'token1'},
            {'Items': [3, 4], 'NextToken': 'token2'},
            {'Items': [5]}
        ])
        result = paginate(mock_method, 'Items', Param='value')
        assert result == [1, 2, 3, 4, 5]
        assert mock_method.call_count == 3


class TestPermissionBoundary:
    @patch('handler.boto3')
    def test_get_permission_boundary_exists(self, mock_boto):
        from handler import get_permission_boundary
        mock_sso = MagicMock()
        mock_sso.get_permissions_boundary_for_permission_set.return_value = {
            'PermissionsBoundary': {'CustomerManagedPolicyReference': {'Name': 'boundary'}}
        }
        result = get_permission_boundary(mock_sso, 'arn:instance', 'arn:ps')
        assert result == {'CustomerManagedPolicyReference': {'Name': 'boundary'}}

    @patch('handler.boto3')
    def test_get_permission_boundary_not_found(self, mock_boto):
        import botocore.exceptions
        from handler import get_permission_boundary
        mock_sso = MagicMock()
        mock_sso.get_permissions_boundary_for_permission_set.side_effect = \
            botocore.exceptions.ClientError(
                {'Error': {'Code': 'ResourceNotFoundException'}},
                'GetPermissionsBoundary'
            )
        result = get_permission_boundary(mock_sso, 'arn:instance', 'arn:ps')
        assert result == ''


class TestManagedPolicies:
    @patch('handler.iam')
    def test_get_managed_policies_success(self, mock_iam):
        from handler import get_managed_policies, paginate
        
        mock_sso = MagicMock()
        mock_sso.list_managed_policies_in_permission_set.return_value = {
            'AttachedManagedPolicies': [{'Arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}]
        }
        
        mock_iam.get_policy.return_value = {
            'Policy': {'DefaultVersionId': 'v1'}
        }
        mock_iam.get_policy_version.return_value = {
            'PolicyVersion': {'Document': {'Version': '2012-10-17', 'Statement': []}}
        }
        
        result = get_managed_policies(mock_sso, 'arn:instance', 'arn:ps')
        
        assert len(result) == 1
        assert result[0]['policyArn'] == 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        assert 'Statement' in result[0]['policyJson']


class TestProcessPermissionSets:
    @patch('handler.get_managed_policies')
    @patch('handler.get_customer_policies')
    @patch('handler.get_permission_boundary')
    def test_process_permission_sets_org_instance(self, mock_boundary, mock_customer, mock_managed):
        from handler import process_permission_sets
        
        mock_sso = MagicMock()
        mock_sso.list_permission_sets.return_value = {
            'PermissionSets': ['arn:aws:sso:::permissionSet/ssoins-123/ps-456']
        }
        mock_sso.list_accounts_for_provisioned_permission_set.return_value = {
            'AccountIds': ['111111111111']
        }
        mock_sso.list_account_assignments.return_value = {
            'AccountAssignments': [{
                'PrincipalId': 'group-id-123',
                'AccountId': '111111111111',
                'PrincipalType': 'GROUP'
            }]
        }
        mock_sso.describe_permission_set.return_value = {
            'PermissionSet': {'Name': 'AdminAccess'}
        }
        mock_sso.get_inline_policy_for_permission_set.return_value = {
            'InlinePolicy': '{"Version":"2012-10-17","Statement":[]}'
        }
        
        mock_managed.return_value = [{'policyArn': 'arn:aws:iam::aws:policy/Admin'}]
        mock_customer.return_value = []
        mock_boundary.return_value = ''
        
        mock_table = MagicMock()
        
        count = process_permission_sets(mock_sso, 'arn:aws:sso:::instance/ssoins-123', mock_table)
        
        assert count == 1
        mock_table.put_item.assert_called_once()
        
        # Verify stored data
        call_args = mock_table.put_item.call_args
        item = call_args[1]['Item']
        assert item['permissionSetName'] == 'AdminAccess'
        assert item['principalId'] == ['group-id-123']
        assert item['accountId'] == ['111111111111']
        assert item['principalType'] == ['GROUP']


class TestProcessUsers:
    def test_process_users_with_groups(self):
        from handler import process_users
        
        mock_identity = MagicMock()
        mock_identity.list_users.return_value = {
            'Users': [{'UserId': 'user-123', 'UserName': 'testuser'}]
        }
        mock_identity.list_group_memberships_for_member.return_value = {
            'GroupMemberships': [{'GroupId': 'group-456'}]
        }
        mock_identity.describe_group.return_value = {
            'DisplayName': 'Developers'
        }
        
        mock_table = MagicMock()
        
        count = process_users(mock_identity, 'd-1234567890', mock_table)
        
        assert count == 1
        mock_table.put_item.assert_called_once()
        
        item = mock_table.put_item.call_args[1]['Item']
        assert item['userId'] == 'user-123'
        assert item['userName'] == 'testuser'
        assert item['groupIds'] == ['group-456']
        assert item['groupName'] == ['Developers']


class TestHandler:
    @patch('handler.process_permission_sets')
    @patch('handler.process_users')
    @patch('handler.ddb')
    @patch('handler.boto3')
    def test_handler_success(self, mock_boto, mock_ddb, mock_users, mock_ps):
        from handler import handler
        
        mock_ps.return_value = 5
        mock_users.return_value = 10
        
        event = {
            'identityStoreId': 'd-1234567890',
            'instanceArn': 'arn:aws:sso:::instance/ssoins-123',
            'ssoDeployedRegion': 'us-east-1'
        }
        
        result = handler(event, None)
        
        assert result['extractionStats']['permissionSets'] == 5
        assert result['extractionStats']['users'] == 10
        assert result['identityStoreId'] == 'd-1234567890'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
