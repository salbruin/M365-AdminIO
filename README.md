# M365 OneDrive Security Scanner

A comprehensive security scanning tool for Microsoft 365 OneDrive environments. This tool helps identify security risks by scanning files for open/public sharing links and sensitive data patterns.

## Features

- **Link Analysis**: Detect various types of sharing links
  - Anyone/Anonymous links (highest risk)
  - Organization-wide links
  - Specific people permissions
  - Permission types (read/write/owner)

- **Sensitive Data Detection**: Identify files containing potentially sensitive information
  - Personal Identifiable Information (PII): SSN, credit cards, phone numbers
  - Credentials: API keys, passwords, tokens, private keys
  - Financial data: bank accounts, IBAN
  - Medical information
  - Government IDs

- **Risk Assessment**: Automated risk scoring and categorization
  - Critical, High, Medium, Low risk levels
  - Comprehensive security reports

- **Multiple Output Formats**:
  - JSON (detailed data)
  - CSV (spreadsheet analysis)
  - HTML (visual reports)

- **Docker Support**: Run in containers for consistent, isolated environments
- **Scheduled Scanning**: Set up automated scans with cron
- **Flexible Configuration**: Environment-based configuration with CLI overrides

## Prerequisites

### Azure AD Application Registration

1. Navigate to [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Configure:
   - **Name**: M365 OneDrive Scanner
   - **Supported account types**: Single tenant
   - **Redirect URI**: Web - `http://localhost:8000`

5. After registration, note down:
   - **Application (client) ID**
   - **Directory (tenant) ID**

6. Create a **Client Secret**:
   - Go to **Certificates & secrets**
   - Click **New client secret**
   - Copy the secret value (only shown once!)

7. Grant **API Permissions**:
   - Go to **API permissions**
   - Click **Add a permission** > **Microsoft Graph** > **Application permissions**
   - Add these permissions:
     - `Files.Read.All`
     - `Sites.Read.All`
     - `User.Read.All`
     - `Reports.Read.All`
   - Click **Grant admin consent for [your tenant]**

## Installation

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/M365-AdminIO.git
cd M365-AdminIO

# Copy environment template
cp .env.example .env

# Edit .env with your Azure AD credentials
nano .env

# Build and run
./run-docker.sh build
./run-docker.sh run
```

### Option 2: Local Python

```bash
# Clone the repository
git clone https://github.com/your-org/M365-AdminIO.git
cd M365-AdminIO

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your Azure AD credentials
nano .env

# Run scanner
python scanner.py
```

## Configuration

### Environment Variables (.env)

```env
# Required: Azure AD credentials
CLIENT_ID=your-client-id-here
TENANT_ID=your-tenant-id-here
CLIENT_SECRET=your-client-secret-here

# Optional: Scanning configuration
SCAN_ALL_USERS=true
SPECIFIC_USERS=user1@domain.com,user2@domain.com

# Optional: Flags
FLAG_ANYONE_LINKS=true
FLAG_ORG_LINKS=false

# Optional: Output
OUTPUT_FORMAT=json,csv,html
OUTPUT_DIR=./reports

# Optional: Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/scanner.log
```

## Usage

### Basic Scan

```bash
# Scan all users (using app-only authentication)
python scanner.py

# Docker
./run-docker.sh run
```

### Scan Specific Users

```bash
python scanner.py --users user1@domain.com user2@domain.com
```

### Interactive Authentication

```bash
# Use delegated permissions (interactive browser login)
python scanner.py --interactive
```

### Filter by Risk Level

```bash
# Show only high or critical risk files
python scanner.py --min-risk high

# Show only files with anyone links
python scanner.py --anyone-links-only
```

### Choose Output Formats

```bash
# Generate only JSON and HTML reports
python scanner.py --formats json html
```

### Custom Output Directory

```bash
python scanner.py --output-dir /path/to/reports
```

### Verbose Logging

```bash
python scanner.py --verbose
```

## Docker Usage

### Quick Start

```bash
# Build image
./run-docker.sh build

# Run single scan
./run-docker.sh run

# Start scheduled scanner (daily at 2 AM)
./run-docker.sh scheduled

# Start web report viewer
./run-docker.sh viewer

# Start all services
./run-docker.sh all

# Stop all services
./run-docker.sh stop

# Clean up resources
./run-docker.sh clean

# Open shell in container
./run-docker.sh shell

# Security scanning
./run-docker.sh security-scan

# Generate SBOM
./run-docker.sh sbom

# Install Trivy
./run-docker.sh install-trivy
```

### Manual Docker Commands

```bash
# Build
docker-compose build

# Run single scan
docker-compose up onedrive-scanner

# Run with custom arguments
docker-compose run --rm onedrive-scanner python scanner.py --min-risk high

# Start scheduled scanner
docker-compose --profile scheduled up -d onedrive-scanner-scheduled

# View reports in browser
docker-compose --profile viewer up -d report-viewer
# Then visit: http://localhost:8080/reports/
```

## Security Scanning

This project includes comprehensive security scanning using [Trivy](https://trivy.dev/) to ensure container security and generate Software Bill of Materials (SBOM).

### Quick Security Scan

```bash
# Install Trivy (first time only)
./run-docker.sh install-trivy

# Run full security scan
./run-docker.sh security-scan

# Generate SBOM
./run-docker.sh sbom
```

### What Gets Scanned

1. **Container Vulnerabilities** - Known CVEs in OS and Python packages
2. **Configuration Issues** - Dockerfile best practices and misconfigurations
3. **Secrets** - Accidentally committed credentials or keys
4. **Dependencies** - Python package vulnerabilities
5. **Licenses** - Open source license compliance

### Security Reports Generated

```
security-reports/
├── dockerfile-scan.txt       # Dockerfile security issues
├── filesystem-scan.txt       # Source code vulnerabilities
├── secret-scan.txt           # Detected secrets
├── image-scan.txt            # Container vulnerabilities (table)
├── image-scan.json           # Container vulnerabilities (JSON)
└── image-scan.html           # Visual HTML report

sbom/
├── sbom_TIMESTAMP_cyclonedx.json  # CycloneDX format (industry standard)
├── sbom_TIMESTAMP_spdx.json       # SPDX format (Linux Foundation)
├── sbom_TIMESTAMP_packages.txt    # Human-readable package list
└── licenses_TIMESTAMP.txt         # License report
```

### CI/CD Integration

Security scans run automatically via GitHub Actions on:
- Every push to main/develop branches
- Every pull request
- Weekly schedule (Monday 2 AM UTC)

Results appear in:
- GitHub Security tab (Code scanning alerts)
- Actions tab (Workflow artifacts)

For detailed security information, see [SECURITY.md](SECURITY.md).

## Output Reports

Reports are generated in the `./reports` directory (or custom path specified).

### JSON Report

Comprehensive report with all scan data:
- User information
- File metadata
- Permissions analysis
- Sensitive data detections
- Risk scores

### CSV Report

Spreadsheet-friendly format with key fields:
- File name and path
- Owner
- Risk level
- Link types
- Sensitive data flags

### HTML Report

Visual report with:
- Executive summary dashboard
- High-risk files table
- Risk distribution charts
- Easy filtering and sorting

## Architecture

```
M365-AdminIO/
├── src/
│   ├── auth/              # M365 OAuth authentication
│   │   └── m365_auth.py
│   ├── scanner/           # OneDrive file scanning
│   │   ├── onedrive_scanner.py
│   │   └── link_analyzer.py
│   ├── detectors/         # Sensitive data detection
│   │   └── sensitive_data_detector.py
│   └── reports/           # Report generation
│       └── report_generator.py
├── scanner.py             # Main entry point
├── Dockerfile             # Docker image definition
├── docker-compose.yml     # Docker orchestration
├── requirements.txt       # Python dependencies
└── .env.example          # Environment template
```

## Security Considerations

### Permissions

This tool requires **read-only** access to OneDrive files via Microsoft Graph API. It does NOT:
- Modify files
- Change permissions
- Delete data
- Access file contents (only metadata and filenames)

### Credential Storage

- Never commit `.env` files to version control
- Store client secrets securely (Azure Key Vault recommended for production)
- Use managed identities when running in Azure
- Rotate secrets regularly

### Data Privacy

- Scan results may contain sensitive information
- Restrict access to report directories
- Consider encryption for report storage
- Follow data retention policies

## Troubleshooting

### Authentication Failed

**Issue**: "Authentication failed. Please check your credentials."

**Solutions**:
1. Verify CLIENT_ID, TENANT_ID, and CLIENT_SECRET in `.env`
2. Ensure API permissions are granted with admin consent
3. Check client secret hasn't expired
4. Verify redirect URI matches Azure AD app registration

### Rate Limiting

**Issue**: "Rate limited" errors during scanning

**Solutions**:
1. The scanner automatically handles rate limiting with retry logic
2. For large tenants, consider scanning specific users in batches
3. Adjust scanning schedule to off-peak hours

### No OneDrive Found

**Issue**: "No OneDrive found" for users

**Solutions**:
1. Verify users have OneDrive enabled
2. Ensure user has accessed OneDrive at least once
3. Check user licenses include OneDrive

### Docker Issues

**Issue**: Container fails to start

**Solutions**:
1. Ensure `.env` file exists
2. Check Docker is running
3. Verify file permissions on mounted volumes
4. Review logs: `docker logs m365-onedrive-scanner`

## Exit Codes

- `0`: Scan completed successfully, no critical issues
- `1`: Warning - organization-wide links detected
- `2`: Critical - anyone/anonymous links detected

## Scheduled Scanning

### Using Docker Compose

The `cron-schedule` file controls scanning frequency:

```cron
# Daily at 2 AM
0 2 * * * cd /app && python scanner.py >> /app/logs/cron.log 2>&1

# Weekly on Monday at 3 AM
0 3 * * 1 cd /app && python scanner.py --min-risk high >> /app/logs/cron.log 2>&1
```

Start scheduled scanner:
```bash
./run-docker.sh scheduled
```

### Using System Cron

```bash
# Add to crontab
crontab -e

# Run daily at 2 AM
0 2 * * * cd /path/to/M365-AdminIO && python scanner.py >> logs/cron.log 2>&1
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: OneDrive Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run scan
        env:
          CLIENT_ID: ${{ secrets.M365_CLIENT_ID }}
          TENANT_ID: ${{ secrets.M365_TENANT_ID }}
          CLIENT_SECRET: ${{ secrets.M365_CLIENT_SECRET }}
        run: python scanner.py --min-risk high

      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: scan-reports
          path: reports/
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check existing issues for solutions
- Review documentation and troubleshooting guide

## Roadmap

- [ ] SharePoint site scanning
- [ ] Teams file scanning
- [ ] Content inspection (download and scan file contents)
- [ ] DLP policy integration
- [ ] Custom sensitivity labels
- [ ] Automated remediation workflows
- [ ] Slack/Teams notifications
- [ ] Database storage for historical tracking
- [ ] Web dashboard UI

## Acknowledgments

Built using:
- Microsoft Graph API
- MSAL (Microsoft Authentication Library)
- Python 3.11+
- Docker

## Disclaimer

This tool is provided as-is for security assessment purposes. Always:
- Test in a non-production environment first
- Review and understand what the tool does
- Comply with your organization's security policies
- Respect user privacy and data protection regulations
