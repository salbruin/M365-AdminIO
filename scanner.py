#!/usr/bin/env python3
"""
M365 OneDrive Security Scanner
Main entry point for scanning OneDrive files for security risks
"""

import os
import sys
import logging
import argparse
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from typing import List, Dict, Any

from src.auth.m365_auth import M365Authenticator
from src.scanner.onedrive_scanner import OneDriveScanner
from src.scanner.link_analyzer import LinkAnalyzer, RiskLevel
from src.detectors.sensitive_data_detector import SensitiveDataDetector, SensitivityLevel
from src.reports.report_generator import ReportGenerator


# Configure logging
def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=handlers
    )


def load_config():
    """Load configuration from environment variables"""
    load_dotenv()

    config = {
        'client_id': os.getenv('CLIENT_ID'),
        'tenant_id': os.getenv('TENANT_ID'),
        'client_secret': os.getenv('CLIENT_SECRET'),
        'redirect_uri': os.getenv('REDIRECT_URI', 'http://localhost:8000'),
        'scan_all_users': os.getenv('SCAN_ALL_USERS', 'true').lower() == 'true',
        'specific_users': os.getenv('SPECIFIC_USERS', '').split(',') if os.getenv('SPECIFIC_USERS') else None,
        'flag_anyone_links': os.getenv('FLAG_ANYONE_LINKS', 'true').lower() == 'true',
        'flag_org_links': os.getenv('FLAG_ORG_LINKS', 'false').lower() == 'true',
        'output_formats': os.getenv('OUTPUT_FORMAT', 'json,csv,html').split(','),
        'output_dir': os.getenv('OUTPUT_DIR', './reports'),
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
        'log_file': os.getenv('LOG_FILE', './logs/scanner.log'),
    }

    # Validate required config
    if not config['client_id']:
        raise ValueError("CLIENT_ID is required in .env file")
    if not config['tenant_id']:
        raise ValueError("TENANT_ID is required in .env file")

    return config


def main():
    """Main scanner function"""
    parser = argparse.ArgumentParser(
        description='M365 OneDrive Security Scanner - Detect open links and sensitive data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all users (requires .env configuration)
  python scanner.py

  # Scan specific users
  python scanner.py --users user1@domain.com user2@domain.com

  # Use interactive authentication
  python scanner.py --interactive

  # Filter by risk level
  python scanner.py --min-risk high

  # Output specific formats
  python scanner.py --formats json html

  # Show only anyone links
  python scanner.py --anyone-links-only
        """
    )

    parser.add_argument(
        '--users',
        nargs='+',
        help='Specific users to scan (userPrincipalName)'
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Use interactive authentication (delegated permissions)'
    )

    parser.add_argument(
        '--min-risk',
        choices=['critical', 'high', 'medium', 'low'],
        default='low',
        help='Minimum risk level to include in reports (default: low)'
    )

    parser.add_argument(
        '--min-sensitivity',
        choices=['critical', 'high', 'medium', 'low'],
        default='low',
        help='Minimum sensitivity level to include in reports (default: low)'
    )

    parser.add_argument(
        '--formats',
        nargs='+',
        choices=['json', 'csv', 'html'],
        default=['json', 'csv', 'html'],
        help='Output formats (default: all)'
    )

    parser.add_argument(
        '--anyone-links-only',
        action='store_true',
        help='Show only files with anyone/anonymous links'
    )

    parser.add_argument(
        '--output-dir',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config()
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        print("Please ensure you have a .env file with required settings.")
        print("See .env.example for reference.")
        sys.exit(1)

    # Override config with command line arguments
    if args.users:
        config['specific_users'] = args.users
        config['scan_all_users'] = False

    if args.output_dir:
        config['output_dir'] = args.output_dir

    if args.verbose:
        config['log_level'] = 'DEBUG'

    # Setup logging
    setup_logging(config['log_level'], config['log_file'])
    logger = logging.getLogger(__name__)

    logger.info("=" * 70)
    logger.info("M365 ONEDRIVE SECURITY SCANNER")
    logger.info("=" * 70)

    # Step 1: Authenticate
    logger.info("Step 1: Authenticating with Microsoft Graph API...")

    authenticator = M365Authenticator(
        client_id=config['client_id'],
        tenant_id=config['tenant_id'],
        client_secret=config['client_secret'],
        redirect_uri=config['redirect_uri']
    )

    auth_headers = authenticator.get_auth_headers(use_app_only=not args.interactive)

    if not auth_headers:
        logger.error("Authentication failed. Please check your credentials.")
        sys.exit(1)

    logger.info("✓ Authentication successful")

    # Step 2: Scan OneDrive files
    logger.info("\nStep 2: Scanning OneDrive files...")

    scanner = OneDriveScanner(auth_headers)

    if config['scan_all_users'] and not config['specific_users']:
        logger.info("Scanning all users in the tenant...")
        scan_results = scanner.scan_all_users()
    else:
        logger.info(f"Scanning specific users: {config['specific_users']}")
        scan_results = scanner.scan_all_users(specific_users=config['specific_users'])

    logger.info(f"✓ Scanned {len(scan_results)} users")

    # Step 3: Analyze links and permissions
    logger.info("\nStep 3: Analyzing file permissions and links...")

    link_analyzer = LinkAnalyzer()
    all_analyzed_files = []

    for user_result in scan_results:
        if not user_result.get('hasOneDrive'):
            continue

        files = user_result.get('files', [])
        user = user_result.get('user', 'unknown')

        for file in files:
            analyzed = link_analyzer.analyze_file_permissions(file)
            analyzed['owner'] = user
            all_analyzed_files.append(analyzed)

    logger.info(f"✓ Analyzed {len(all_analyzed_files)} files")

    # Step 4: Detect sensitive data
    logger.info("\nStep 4: Detecting sensitive data in filenames...")

    sensitive_detector = SensitiveDataDetector()

    for file in all_analyzed_files:
        sensitive_analysis = sensitive_detector.analyze_file(file)

        # Merge sensitive data analysis into file
        file['hasSensitiveData'] = sensitive_analysis['hasSensitiveData']
        file['detections'] = sensitive_analysis['detections']
        file['detectionCount'] = sensitive_analysis['detectionCount']
        file['highestSensitivityLevel'] = sensitive_analysis['highestSensitivityLevel']
        file['sensitivityScore'] = sensitive_analysis['sensitivityScore']

    logger.info(f"✓ Sensitive data detection complete")

    # Step 5: Filter results
    logger.info("\nStep 5: Filtering results...")

    # Filter by anyone links if specified
    if args.anyone_links_only:
        all_analyzed_files = link_analyzer.get_anyone_links(all_analyzed_files)
        logger.info(f"Filtered to {len(all_analyzed_files)} files with anyone links")

    # Filter by minimum risk level
    min_risk = RiskLevel[args.min_risk.upper()]
    filtered_files = link_analyzer.filter_by_risk(all_analyzed_files, min_risk)
    logger.info(f"Filtered to {len(filtered_files)} files with {args.min_risk}+ risk")

    # Step 6: Generate reports
    logger.info("\nStep 6: Generating reports...")

    report_gen = ReportGenerator(output_dir=config['output_dir'])

    # Generate summaries
    link_summary = link_analyzer.generate_summary(all_analyzed_files)
    sensitive_summary = sensitive_detector.generate_summary(all_analyzed_files)

    combined_summary = {
        **link_summary,
        'filesWithSensitiveData': sensitive_summary['filesWithSensitiveData'],
        'sensitivityDistribution': sensitive_summary['sensitivityDistribution']
    }

    report_data = {
        'scanTime': datetime.utcnow().isoformat(),
        'usersScanned': len(scan_results),
        'summary': combined_summary,
        'files': all_analyzed_files,
        'filteredFiles': filtered_files
    }

    # Generate in requested formats
    generated_reports = []

    if 'json' in args.formats:
        json_report = report_gen.generate_json_report(report_data)
        generated_reports.append(json_report)
        logger.info(f"✓ JSON report: {json_report}")

    if 'csv' in args.formats:
        csv_report = report_gen.generate_csv_report(filtered_files)
        generated_reports.append(csv_report)
        logger.info(f"✓ CSV report: {csv_report}")

    if 'html' in args.formats:
        html_report = report_gen.generate_html_report(report_data)
        generated_reports.append(html_report)
        logger.info(f"✓ HTML report: {html_report}")

    # Print summary to console
    report_gen.print_summary(report_data)

    logger.info("\n" + "=" * 70)
    logger.info("SCAN COMPLETE")
    logger.info("=" * 70)
    logger.info(f"\nGenerated {len(generated_reports)} report(s):")
    for report in generated_reports:
        logger.info(f"  - {report}")

    # Return exit code based on findings
    if combined_summary.get('anyoneLinksCount', 0) > 0:
        logger.warning("\n⚠ WARNING: Files with anyone links detected!")
        return 2
    elif combined_summary.get('orgWideLinksCount', 0) > 0:
        logger.warning("\n⚠ WARNING: Files with organization-wide links detected!")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
