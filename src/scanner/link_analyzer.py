"""
Link Analyzer Module
Analyzes sharing links and permissions on OneDrive files
"""

import logging
from typing import Dict, Any, List
from enum import Enum

logger = logging.getLogger(__name__)


class LinkType(Enum):
    """Types of sharing links"""
    ANONYMOUS = "anonymous"  # Anyone with link (most risky)
    ORGANIZATION = "organization"  # Anyone in organization
    SPECIFIC_PEOPLE = "users"  # Specific people only
    DIRECT = "direct"  # Direct permission (not a link)
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk levels for file sharing"""
    CRITICAL = "critical"  # Anonymous/Anyone links
    HIGH = "high"  # Organization-wide links
    MEDIUM = "medium"  # Specific people with edit
    LOW = "low"  # Specific people read-only
    NONE = "none"  # No sharing


class LinkAnalyzer:
    """
    Analyzes OneDrive file permissions and sharing links
    Identifies risky sharing configurations
    """

    def __init__(self):
        """Initialize link analyzer"""
        pass

    def analyze_permission(self, permission: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single permission object

        Args:
            permission: Permission object from Graph API

        Returns:
            Analyzed permission with risk level and type
        """
        analysis = {
            'id': permission.get('id'),
            'hasPassword': permission.get('hasPassword', False),
            'grantedTo': None,
            'grantedToIdentities': [],
            'roles': permission.get('roles', []),
            'linkType': LinkType.UNKNOWN.value,
            'riskLevel': RiskLevel.NONE.value,
            'expirationDateTime': permission.get('expirationDateTime'),
            'link': permission.get('link', {})
        }

        # Check if it's a sharing link
        if 'link' in permission:
            link = permission['link']
            scope = link.get('scope', 'unknown')
            link_type = link.get('type', 'unknown')

            # Determine link type and risk
            if scope == 'anonymous':
                analysis['linkType'] = LinkType.ANONYMOUS.value
                analysis['riskLevel'] = RiskLevel.CRITICAL.value
                analysis['riskReason'] = "Anyone with the link can access (anonymous link)"

            elif scope == 'organization':
                analysis['linkType'] = LinkType.ORGANIZATION.value
                analysis['riskLevel'] = RiskLevel.HIGH.value
                analysis['riskReason'] = "Anyone in the organization can access"

            elif scope == 'users':
                analysis['linkType'] = LinkType.SPECIFIC_PEOPLE.value

                # Check if they have edit permissions
                if 'write' in analysis['roles'] or 'owner' in analysis['roles']:
                    analysis['riskLevel'] = RiskLevel.MEDIUM.value
                    analysis['riskReason'] = "Specific people can edit"
                else:
                    analysis['riskLevel'] = RiskLevel.LOW.value
                    analysis['riskReason'] = "Specific people can read"

            # Check for password protection (reduces risk slightly)
            if analysis['hasPassword']:
                analysis['riskReason'] = f"{analysis.get('riskReason', '')} (password protected)"

            # Check for expiration (reduces risk)
            if analysis['expirationDateTime']:
                analysis['riskReason'] = f"{analysis.get('riskReason', '')} (expires: {analysis['expirationDateTime']})"

        # Direct permission (not a link)
        elif 'grantedTo' in permission or 'grantedToIdentities' in permission:
            analysis['linkType'] = LinkType.DIRECT.value

            if 'grantedTo' in permission:
                analysis['grantedTo'] = permission['grantedTo'].get('user', {})

            if 'grantedToIdentities' in permission:
                analysis['grantedToIdentities'] = [
                    identity.get('user', {}) for identity in permission['grantedToIdentities']
                ]

            # Check roles for direct permissions
            if 'write' in analysis['roles'] or 'owner' in analysis['roles']:
                analysis['riskLevel'] = RiskLevel.MEDIUM.value
                analysis['riskReason'] = "Direct edit permission granted"
            else:
                analysis['riskLevel'] = RiskLevel.LOW.value
                analysis['riskReason'] = "Direct read permission granted"

        return analysis

    def analyze_file_permissions(self, file_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all permissions for a file

        Args:
            file_item: File item from OneDrive with permissions

        Returns:
            Analysis results with highest risk level and all permissions
        """
        permissions = file_item.get('permissions', [])

        if not permissions:
            return {
                'fileId': file_item.get('id'),
                'fileName': file_item.get('name'),
                'filePath': file_item.get('parentReference', {}).get('path', ''),
                'webUrl': file_item.get('webUrl'),
                'size': file_item.get('size', 0),
                'createdDateTime': file_item.get('createdDateTime'),
                'lastModifiedDateTime': file_item.get('lastModifiedDateTime'),
                'hasSharing': False,
                'permissionCount': 0,
                'analyzedPermissions': [],
                'highestRiskLevel': RiskLevel.NONE.value,
                'riskScore': 0
            }

        # Analyze each permission
        analyzed_permissions = [self.analyze_permission(perm) for perm in permissions]

        # Determine highest risk
        risk_order = {
            RiskLevel.CRITICAL.value: 4,
            RiskLevel.HIGH.value: 3,
            RiskLevel.MEDIUM.value: 2,
            RiskLevel.LOW.value: 1,
            RiskLevel.NONE.value: 0
        }

        highest_risk = max(
            analyzed_permissions,
            key=lambda p: risk_order.get(p['riskLevel'], 0)
        )

        # Count different link types
        link_types = {}
        for perm in analyzed_permissions:
            link_type = perm['linkType']
            link_types[link_type] = link_types.get(link_type, 0) + 1

        return {
            'fileId': file_item.get('id'),
            'fileName': file_item.get('name'),
            'filePath': file_item.get('parentReference', {}).get('path', ''),
            'webUrl': file_item.get('webUrl'),
            'size': file_item.get('size', 0),
            'mimeType': file_item.get('file', {}).get('mimeType'),
            'createdDateTime': file_item.get('createdDateTime'),
            'lastModifiedDateTime': file_item.get('lastModifiedDateTime'),
            'createdBy': file_item.get('createdBy', {}).get('user', {}),
            'lastModifiedBy': file_item.get('lastModifiedBy', {}).get('user', {}),
            'hasSharing': True,
            'permissionCount': len(permissions),
            'analyzedPermissions': analyzed_permissions,
            'highestRiskLevel': highest_risk['riskLevel'],
            'riskScore': risk_order.get(highest_risk['riskLevel'], 0),
            'linkTypeCounts': link_types
        }

    def filter_by_risk(self, analyzed_files: List[Dict[str, Any]],
                       min_risk_level: RiskLevel = RiskLevel.LOW) -> List[Dict[str, Any]]:
        """
        Filter files by minimum risk level

        Args:
            analyzed_files: List of analyzed file results
            min_risk_level: Minimum risk level to include

        Returns:
            Filtered list of files
        """
        risk_order = {
            RiskLevel.CRITICAL.value: 4,
            RiskLevel.HIGH.value: 3,
            RiskLevel.MEDIUM.value: 2,
            RiskLevel.LOW.value: 1,
            RiskLevel.NONE.value: 0
        }

        min_score = risk_order.get(min_risk_level.value, 0)

        return [
            f for f in analyzed_files
            if risk_order.get(f['highestRiskLevel'], 0) >= min_score
        ]

    def get_anyone_links(self, analyzed_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get all files with anonymous/anyone links (highest risk)

        Args:
            analyzed_files: List of analyzed file results

        Returns:
            Files with anyone links
        """
        return [
            f for f in analyzed_files
            if any(p['linkType'] == LinkType.ANONYMOUS.value
                   for p in f.get('analyzedPermissions', []))
        ]

    def get_org_wide_links(self, analyzed_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get all files with organization-wide links

        Args:
            analyzed_files: List of analyzed file results

        Returns:
            Files with org-wide links
        """
        return [
            f for f in analyzed_files
            if any(p['linkType'] == LinkType.ORGANIZATION.value
                   for p in f.get('analyzedPermissions', []))
        ]

    def generate_summary(self, analyzed_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for analyzed files

        Args:
            analyzed_files: List of analyzed file results

        Returns:
            Summary statistics
        """
        total_files = len(analyzed_files)
        files_with_sharing = sum(1 for f in analyzed_files if f['hasSharing'])

        anyone_links = self.get_anyone_links(analyzed_files)
        org_links = self.get_org_wide_links(analyzed_files)

        risk_counts = {
            RiskLevel.CRITICAL.value: 0,
            RiskLevel.HIGH.value: 0,
            RiskLevel.MEDIUM.value: 0,
            RiskLevel.LOW.value: 0,
            RiskLevel.NONE.value: 0
        }

        for file in analyzed_files:
            risk_level = file['highestRiskLevel']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

        return {
            'totalFiles': total_files,
            'filesWithSharing': files_with_sharing,
            'filesWithoutSharing': total_files - files_with_sharing,
            'anyoneLinksCount': len(anyone_links),
            'orgWideLinksCount': len(org_links),
            'riskDistribution': risk_counts,
            'totalSize': sum(f['size'] for f in analyzed_files),
            'averagePermissionsPerFile': sum(f['permissionCount'] for f in analyzed_files) / total_files if total_files > 0 else 0
        }
