"""Unit tests for data transform function."""

import pytest
from unittest.mock import MagicMock, patch, mock_open
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PERMISSION_TABLE_NAME'] = 'test-permissions'
os.environ['USER_TABLE_NAME'] = 'test-users'
os.environ['TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'
os.environ['BUCKET_NAME'] = 'test-bucket'
os.environ['LOG_LEVEL'] = 'DEBUG'


class TestScanTable:
    def test_scan_single_page(self):
        from handler import scan_table
        mock_table = MagicMock()
        mock_table.scan.return_value = {'Items': [{'id': '1'}, {'id': '2'}]}
        
        result = scan_table(mock_table)
        assert len(result) == 2

    def test_scan_multiple_pages(self):
        from handler import scan_table
        mock_table = MagicMock()
        mock_table.scan.side_effect = [
            {'Items': [{'id': '1'}], 'LastEvaluatedKey': {'id': '1'}},
            {'Items': [{'id': '2'}]}
        ]
        
        result = scan_table(mock_table)
        assert len(result) == 2


class TestQueryPermissions:
    def test_query_with_results(self):
        from handler import query_permissions
        mock_table = MagicMock()
        mock_table.query.return_value = {
            'Items': [{
                'permissionSetArn': 'arn:ps',
                'permissionSetName': 'Admin',
                'principalId': ['user-123'],
                'accountId': ['111111111111'],
                'principalType': ['USER']
            }]
        }
        
        result = query_permissions(mock_table, 'arn:instance', 'user-123')
        assert len(result) == 1
        assert result[0]['permissionSetName'] == 'Admin'

    def test_query_no_results(self):
        from handler import query_permissions
        mock_table = MagicMock()
        mock_table.query.return_value = {'Items': []}
        
        result = query_permissions(mock_table, 'arn:instance', 'user-123')
        assert result == []


class TestTruncate:
    def test_truncate_short_value(self):
        from handler import truncate_for_excel
        result = truncate_for_excel('short string')
        assert result == 'short string'

    def test_truncate_long_value(self):
        from handler import truncate_for_excel, EXCEL_CHAR_LIMIT
        long_string = 'x' * (EXCEL_CHAR_LIMIT + 100)
        result = truncate_for_excel(long_string)
        assert 'Excel limit' in result


class TestWriteUserPermissions:
    def test_write_no_permissions(self):
        from handler import write_user_permissions
        
        mock_writer = MagicMock()
        mock_table = MagicMock()
        mock_table.query.return_value = {'Items': []}
        
        rows = write_user_permissions(
            mock_writer, 'testuser', 'user-123', '', mock_table, 'arn:instance'
        )
        
        assert rows == 1
        mock_writer.writerow.assert_called_once()
        call_args = mock_writer.writerow.call_args[0][0]
        assert call_args[0] == 'testuser'
        assert call_args[4] == 'not_assigned'

    def test_write_with_permissions(self):
        from handler import write_user_permissions
        
        mock_writer = MagicMock()
        mock_table = MagicMock()
        mock_table.query.return_value = {
            'Items': [{
                'permissionSetArn': 'arn:ps',
                'permissionSetName': 'AdminAccess',
                'principalId': ['user-123'],
                'accountId': ['111111111111'],
                'principalType': ['USER'],
                'inlinePolicies': '{}',
                'customerPolicies': [],
                'managedPolicies': [{'policyArn': 'arn:aws:iam::aws:policy/Admin'}],
                'permissionsBoundary': ''
            }]
        }
        
        rows = write_user_permissions(
            mock_writer, 'testuser', 'user-123', '', mock_table, 'arn:instance'
        )
        
        assert rows == 1
        call_args = mock_writer.writerow.call_args[0][0]
        assert call_args[0] == 'testuser'
        assert call_args[4] == '111111111111'
        assert call_args[6] == 'AdminAccess'


class TestGenerateReport:
    @patch('builtins.open', mock_open())
    def test_generate_report_with_users(self):
        from handler import generate_report
        
        users = [{
            'userId': 'user-123',
            'userName': 'testuser',
            'groupIds': ['group-456'],
            'groupName': ['Developers']
        }]
        
        mock_table = MagicMock()
        mock_table.query.return_value = {'Items': []}
        
        rows = generate_report(users, mock_table, 'arn:instance', '/tmp/test.csv')
        
        # 1 row for user direct + 1 row for group
        assert rows == 2


class TestHandler:
    @patch('handler.scan_table')
    @patch('handler.generate_report')
    @patch('handler.s3')
    @patch('handler.sns')
    @patch('handler.ddb')
    def test_handler_success(self, mock_ddb, mock_sns, mock_s3, mock_report, mock_scan):
        from handler import handler
        
        mock_scan.return_value = [{'userId': 'u1', 'userName': 'user1', 'groupIds': [], 'groupName': []}]
        mock_report.return_value = 5
        
        event = {
            'Payload': {
                'instanceArn': 'arn:aws:sso:::instance/ssoins-123'
            }
        }
        
        result = handler(event, None)
        
        assert result['status'] == 'success'
        assert result['report']['rowCount'] == 5
        mock_s3.upload_file.assert_called_once()
        mock_sns.publish.assert_called_once()

    @patch('handler.scan_table')
    @patch('handler.generate_report')
    @patch('handler.s3')
    @patch('handler.sns')
    @patch('handler.ddb')
    def test_handler_nested_payload(self, mock_ddb, mock_sns, mock_s3, mock_report, mock_scan):
        from handler import handler
        
        mock_scan.return_value = []
        mock_report.return_value = 0
        
        # Test nested Payload structure from Step Functions
        event = {
            'Payload': {
                'Payload': {
                    'instanceArn': 'arn:aws:sso:::instance/ssoins-123'
                }
            }
        }
        
        result = handler(event, None)
        assert result['status'] == 'success'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
