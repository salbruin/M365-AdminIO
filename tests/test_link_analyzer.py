"""
Unit tests for LinkAnalyzer
"""

import pytest
from src.scanner.link_analyzer import LinkAnalyzer, LinkType, RiskLevel


class TestLinkAnalyzer:
    """Test LinkAnalyzer functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = LinkAnalyzer()

    def test_analyze_anonymous_link(self):
        """Test detection of anonymous/anyone links"""
        permission = {
            'id': '123',
            'link': {
                'scope': 'anonymous',
                'type': 'view'
            },
            'roles': ['read']
        }

        result = self.analyzer.analyze_permission(permission)

        assert result['linkType'] == LinkType.ANONYMOUS.value
        assert result['riskLevel'] == RiskLevel.CRITICAL.value

    def test_analyze_organization_link(self):
        """Test detection of organization-wide links"""
        permission = {
            'id': '456',
            'link': {
                'scope': 'organization',
                'type': 'view'
            },
            'roles': ['read']
        }

        result = self.analyzer.analyze_permission(permission)

        assert result['linkType'] == LinkType.ORGANIZATION.value
        assert result['riskLevel'] == RiskLevel.HIGH.value

    def test_analyze_specific_people_link(self):
        """Test detection of specific people links"""
        permission = {
            'id': '789',
            'link': {
                'scope': 'users',
                'type': 'view'
            },
            'roles': ['read']
        }

        result = self.analyzer.analyze_permission(permission)

        assert result['linkType'] == LinkType.SPECIFIC_PEOPLE.value
        assert result['riskLevel'] == RiskLevel.LOW.value

    def test_password_protected_link(self):
        """Test that password protection is noted"""
        permission = {
            'id': '999',
            'link': {
                'scope': 'anonymous',
                'type': 'view'
            },
            'roles': ['read'],
            'hasPassword': True
        }

        result = self.analyzer.analyze_permission(permission)

        assert result['hasPassword'] is True
        assert 'password protected' in result.get('riskReason', '').lower()

    def test_file_with_multiple_permissions(self):
        """Test analyzing file with multiple permissions"""
        file_item = {
            'id': 'file1',
            'name': 'test.docx',
            'permissions': [
                {
                    'id': '1',
                    'link': {'scope': 'anonymous', 'type': 'view'},
                    'roles': ['read']
                },
                {
                    'id': '2',
                    'link': {'scope': 'organization', 'type': 'view'},
                    'roles': ['read']
                }
            ]
        }

        result = self.analyzer.analyze_file_permissions(file_item)

        assert result['permissionCount'] == 2
        assert result['hasSharing'] is True
        assert result['highestRiskLevel'] == RiskLevel.CRITICAL.value

    def test_filter_anyone_links(self):
        """Test filtering files with anyone links"""
        files = [
            {
                'analyzedPermissions': [
                    {'linkType': LinkType.ANONYMOUS.value}
                ]
            },
            {
                'analyzedPermissions': [
                    {'linkType': LinkType.ORGANIZATION.value}
                ]
            }
        ]

        anyone_links = self.analyzer.get_anyone_links(files)

        assert len(anyone_links) == 1

    def test_generate_summary(self):
        """Test summary generation"""
        files = [
            {
                'hasSharing': True,
                'permissionCount': 2,
                'highestRiskLevel': RiskLevel.CRITICAL.value,
                'size': 1024,
                'analyzedPermissions': [
                    {'linkType': LinkType.ANONYMOUS.value}
                ]
            },
            {
                'hasSharing': False,
                'permissionCount': 0,
                'highestRiskLevel': RiskLevel.NONE.value,
                'size': 2048,
                'analyzedPermissions': []
            }
        ]

        summary = self.analyzer.generate_summary(files)

        assert summary['totalFiles'] == 2
        assert summary['filesWithSharing'] == 1
        assert summary['anyoneLinksCount'] == 1
        assert summary['totalSize'] == 3072
