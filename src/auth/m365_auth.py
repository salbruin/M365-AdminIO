"""
M365 Authentication Module
Handles OAuth authentication with Microsoft Graph API
"""

import os
import logging
from typing import Optional, Dict, Any
from msal import ConfidentialClientApplication, PublicClientApplication
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

logger = logging.getLogger(__name__)


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth redirect"""

    auth_code = None

    def do_GET(self):
        """Handle GET request with authorization code"""
        query = urlparse(self.path).query
        params = parse_qs(query)

        if 'code' in params:
            RedirectHandler.auth_code = params['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <body>
                    <h1>Authentication Successful!</h1>
                    <p>You can close this window and return to the application.</p>
                </body>
                </html>
            """)
        else:
            self.send_response(400)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress server log messages"""
        pass


class M365Authenticator:
    """
    Handles authentication with Microsoft 365 Graph API
    Supports both interactive (delegated) and application permissions
    """

    # Required Graph API scopes
    SCOPES = [
        "Files.Read.All",
        "Sites.Read.All",
        "User.Read.All",
        "Reports.Read.All"
    ]

    AUTHORITY = "https://login.microsoftonline.com/{tenant_id}"
    GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

    def __init__(self,
                 client_id: str,
                 tenant_id: str,
                 client_secret: Optional[str] = None,
                 redirect_uri: str = "http://localhost:8000"):
        """
        Initialize authenticator

        Args:
            client_id: Azure AD Application (Client) ID
            tenant_id: Azure AD Tenant ID
            client_secret: Client secret (for app-only auth)
            redirect_uri: Redirect URI for interactive auth
        """
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authority = self.AUTHORITY.format(tenant_id=tenant_id)
        self.token_cache = {}

        logger.info(f"Initialized M365 Authenticator for tenant: {tenant_id}")

    def get_app_only_token(self) -> Optional[str]:
        """
        Get access token using application permissions (client credentials)
        Requires CLIENT_SECRET to be set

        Returns:
            Access token string or None if authentication fails
        """
        if not self.client_secret:
            logger.error("Client secret required for app-only authentication")
            return None

        try:
            app = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=self.authority
            )

            # Use .default scope for app-only
            scopes = ["https://graph.microsoft.com/.default"]

            result = app.acquire_token_silent(scopes, account=None)

            if not result:
                logger.info("No cached token found, acquiring new token...")
                result = app.acquire_token_for_client(scopes=scopes)

            if "access_token" in result:
                logger.info("Successfully acquired app-only access token")
                return result["access_token"]
            else:
                logger.error(f"Authentication failed: {result.get('error_description', 'Unknown error')}")
                return None

        except Exception as e:
            logger.error(f"Error during app-only authentication: {str(e)}")
            return None

    def get_delegated_token_interactive(self) -> Optional[str]:
        """
        Get access token using delegated permissions (interactive login)
        Opens browser for user to authenticate

        Returns:
            Access token string or None if authentication fails
        """
        try:
            app = PublicClientApplication(
                client_id=self.client_id,
                authority=self.authority
            )

            # Try to get cached token first
            accounts = app.get_accounts()
            result = None

            if accounts:
                logger.info("Found cached account, attempting silent authentication...")
                result = app.acquire_token_silent(self.SCOPES, account=accounts[0])

            if not result:
                logger.info("Starting interactive authentication flow...")

                # Start local server to receive redirect
                server = HTTPServer(('localhost', 8000), RedirectHandler)
                server_thread = threading.Thread(target=server.handle_request)
                server_thread.start()

                # Get authorization URL
                flow = app.initiate_auth_code_flow(
                    scopes=self.SCOPES,
                    redirect_uri=self.redirect_uri
                )

                if "auth_uri" not in flow:
                    logger.error("Failed to create authorization URL")
                    return None

                # Open browser for user authentication
                print(f"\nOpening browser for authentication...")
                print(f"If browser doesn't open, visit: {flow['auth_uri']}\n")
                webbrowser.open(flow['auth_uri'])

                # Wait for redirect
                server_thread.join(timeout=300)  # 5 minute timeout

                if RedirectHandler.auth_code:
                    result = app.acquire_token_by_auth_code_flow(
                        auth_code_flow=flow,
                        auth_response={'code': RedirectHandler.auth_code}
                    )
                else:
                    logger.error("No authorization code received")
                    return None

            if result and "access_token" in result:
                logger.info("Successfully acquired delegated access token")
                return result["access_token"]
            else:
                logger.error(f"Authentication failed: {result.get('error_description', 'Unknown error') if result else 'No result'}")
                return None

        except Exception as e:
            logger.error(f"Error during interactive authentication: {str(e)}")
            return None

    def get_token(self, use_app_only: bool = True) -> Optional[str]:
        """
        Get access token (app-only by default, interactive if specified)

        Args:
            use_app_only: Use application permissions if True, delegated if False

        Returns:
            Access token string or None if authentication fails
        """
        if use_app_only:
            return self.get_app_only_token()
        else:
            return self.get_delegated_token_interactive()

    def get_auth_headers(self, use_app_only: bool = True) -> Optional[Dict[str, str]]:
        """
        Get authorization headers for Graph API requests

        Args:
            use_app_only: Use application permissions if True, delegated if False

        Returns:
            Dictionary with authorization header or None if authentication fails
        """
        token = self.get_token(use_app_only=use_app_only)

        if token:
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

        return None
