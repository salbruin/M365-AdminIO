"""
OneDrive Scanner Module
Scans OneDrive files and folders for shared links and permissions
"""

import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class OneDriveScanner:
    """
    Scans OneDrive files across an M365 tenant
    Identifies shared links, permissions, and file metadata
    """

    GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"
    BATCH_SIZE = 100  # Graph API pagination size

    def __init__(self, auth_headers: Dict[str, str]):
        """
        Initialize scanner with authentication headers

        Args:
            auth_headers: Authorization headers from M365Authenticator
        """
        self.auth_headers = auth_headers
        self.session = requests.Session()
        self.session.headers.update(auth_headers)

    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all users in the tenant

        Returns:
            List of user objects with id, userPrincipalName, displayName
        """
        users = []
        url = f"{self.GRAPH_ENDPOINT}/users"
        params = {
            "$select": "id,userPrincipalName,displayName,mail",
            "$top": self.BATCH_SIZE
        }

        try:
            while url:
                response = self.session.get(url, params=params if url == f"{self.GRAPH_ENDPOINT}/users" else None)

                if response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()

                users.extend(data.get('value', []))
                url = data.get('@odata.nextLink')

                logger.info(f"Retrieved {len(users)} users so far...")

            logger.info(f"Total users retrieved: {len(users)}")
            return users

        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving users: {str(e)}")
            return []

    def get_user_drive(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user's OneDrive drive information

        Args:
            user_id: User's ID or userPrincipalName

        Returns:
            Drive object or None if not found
        """
        try:
            url = f"{self.GRAPH_ENDPOINT}/users/{user_id}/drive"
            response = self.session.get(url)

            if response.status_code == 404:
                logger.debug(f"No OneDrive found for user: {user_id}")
                return None

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return self.get_user_drive(user_id)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving drive for user {user_id}: {str(e)}")
            return None

    def get_drive_items(self, user_id: str, folder_id: str = "root") -> List[Dict[str, Any]]:
        """
        Get all items in a drive folder recursively

        Args:
            user_id: User's ID or userPrincipalName
            folder_id: Folder ID (default: root)

        Returns:
            List of drive items
        """
        items = []

        try:
            url = f"{self.GRAPH_ENDPOINT}/users/{user_id}/drive/items/{folder_id}/children"
            params = {
                "$top": self.BATCH_SIZE,
                "$expand": "permissions"
            }

            while url:
                response = self.session.get(url, params=params if '?' not in url else None)

                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()

                for item in data.get('value', []):
                    items.append(item)

                    # Recursively scan folders
                    if 'folder' in item:
                        logger.debug(f"Scanning folder: {item['name']}")
                        items.extend(self.get_drive_items(user_id, item['id']))

                url = data.get('@odata.nextLink')

            return items

        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving drive items for user {user_id}: {str(e)}")
            return []

    def get_item_permissions(self, user_id: str, item_id: str) -> List[Dict[str, Any]]:
        """
        Get detailed permissions for a specific item

        Args:
            user_id: User's ID or userPrincipalName
            item_id: Item ID

        Returns:
            List of permission objects
        """
        try:
            url = f"{self.GRAPH_ENDPOINT}/users/{user_id}/drive/items/{item_id}/permissions"
            response = self.session.get(url)

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return self.get_item_permissions(user_id, item_id)

            response.raise_for_status()
            data = response.json()

            return data.get('value', [])

        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving permissions for item {item_id}: {str(e)}")
            return []

    def scan_user_onedrive(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan a user's entire OneDrive for files and shared links

        Args:
            user: User object with id and userPrincipalName

        Returns:
            Dictionary with scan results
        """
        user_id = user['id']
        user_principal_name = user.get('userPrincipalName', 'unknown')

        logger.info(f"Scanning OneDrive for: {user_principal_name}")

        # Get user's drive
        drive = self.get_user_drive(user_id)

        if not drive:
            return {
                'user': user_principal_name,
                'userId': user_id,
                'hasOneDrive': False,
                'files': [],
                'error': 'No OneDrive found'
            }

        # Get all drive items
        items = self.get_drive_items(user_id)

        # Filter to files only (exclude folders)
        files = [item for item in items if 'file' in item]

        logger.info(f"Found {len(files)} files for {user_principal_name}")

        return {
            'user': user_principal_name,
            'userId': user_id,
            'hasOneDrive': True,
            'driveId': drive['id'],
            'files': files,
            'scanTime': datetime.utcnow().isoformat(),
            'fileCount': len(files),
            'totalSize': sum(item.get('size', 0) for item in files)
        }

    def scan_all_users(self, specific_users: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan OneDrive for all users or specific users

        Args:
            specific_users: List of userPrincipalNames to scan (None = all users)

        Returns:
            List of scan results for each user
        """
        # Get all users
        all_users = self.get_all_users()

        if specific_users:
            # Filter to specific users
            all_users = [u for u in all_users if u.get('userPrincipalName') in specific_users]
            logger.info(f"Filtering to {len(all_users)} specific users")

        results = []

        for user in all_users:
            try:
                result = self.scan_user_onedrive(user)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning user {user.get('userPrincipalName', 'unknown')}: {str(e)}")
                results.append({
                    'user': user.get('userPrincipalName', 'unknown'),
                    'userId': user['id'],
                    'hasOneDrive': False,
                    'files': [],
                    'error': str(e)
                })

        return results
