# M365 OneDrive Scanner - Complete Setup Guide

This guide walks you through setting up the OneDrive Security Scanner from scratch.

## Table of Contents

1. [Azure AD App Registration](#1-azure-ad-app-registration)
2. [Configure Permissions](#2-configure-permissions)
3. [Local Setup](#3-local-setup)
4. [Docker Setup](#4-docker-setup)
5. [First Scan](#5-first-scan)
6. [Scheduled Scanning](#6-scheduled-scanning)

---

## 1. Azure AD App Registration

### Step 1.1: Create App Registration

1. Navigate to [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory**
3. Click **App registrations** (left menu)
4. Click **+ New registration**

### Step 1.2: Configure Registration

Fill in the registration form:

- **Name**: `M365 OneDrive Security Scanner`
- **Supported account types**:
  - Select **"Accounts in this organizational directory only (Single tenant)"**
- **Redirect URI**:
  - Platform: **Web**
  - URI: `http://localhost:8000`

Click **Register**

### Step 1.3: Copy Credentials

After registration, you'll see the overview page. **Copy these values**:

1. **Application (client) ID**
   - Found under "Essentials"
   - Example: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

2. **Directory (tenant) ID**
   - Found under "Essentials"
   - Example: `12345678-1234-1234-1234-123456789012`

Save these in a secure location - you'll need them later.

---

## 2. Configure Permissions

### Step 2.1: Create Client Secret

1. In your app registration, click **Certificates & secrets** (left menu)
2. Click **+ New client secret**
3. Add description: `OneDrive Scanner Secret`
4. Select expiration: **24 months** (or as per your policy)
5. Click **Add**
6. **IMPORTANT**: Copy the **Value** immediately (it won't be shown again!)
   - Example: `abc123~DEF456.ghi789-JKL012_mno345`

### Step 2.2: Add API Permissions

1. Click **API permissions** (left menu)
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Select **Application permissions** (not Delegated)

Add these permissions:

| Permission | Type | Description |
|------------|------|-------------|
| `Files.Read.All` | Application | Read files in all site collections |
| `Sites.Read.All` | Application | Read items in all site collections |
| `User.Read.All` | Application | Read all users' full profiles |
| `Reports.Read.All` | Application | Read usage reports |

5. Click **Add permissions**

### Step 2.3: Grant Admin Consent

**CRITICAL STEP**: Permissions won't work without admin consent!

1. Click **Grant admin consent for [Your Organization]**
2. Click **Yes** in the confirmation dialog
3. Wait for status to show green checkmarks

You should see "Granted for [Your Organization]" in the Status column.

---

## 3. Local Setup

### Step 3.1: Prerequisites

Ensure you have:
- Python 3.11 or higher
- Git
- pip (Python package manager)

Check versions:
```bash
python3 --version  # Should be 3.11+
pip3 --version
git --version
```

### Step 3.2: Clone Repository

```bash
git clone https://github.com/your-org/M365-AdminIO.git
cd M365-AdminIO
```

### Step 3.3: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

Your prompt should now show `(venv)`.

### Step 3.4: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required Python packages.

### Step 3.5: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your credentials
nano .env  # or use your preferred editor
```

Fill in your Azure AD credentials:

```env
# REQUIRED: Replace with your values from Step 1.3 and 2.1
CLIENT_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890
TENANT_ID=12345678-1234-1234-1234-123456789012
CLIENT_SECRET=abc123~DEF456.ghi789-JKL012_mno345

# Optional: Leave defaults or customize
REDIRECT_URI=http://localhost:8000
SCAN_ALL_USERS=true
FLAG_ANYONE_LINKS=true
OUTPUT_FORMAT=json,csv,html
OUTPUT_DIR=./reports
LOG_LEVEL=INFO
```

Save and close the file.

---

## 4. Docker Setup

### Step 4.1: Prerequisites

Install Docker:
- [Docker Desktop for Windows/Mac](https://www.docker.com/products/docker-desktop)
- [Docker Engine for Linux](https://docs.docker.com/engine/install/)

Verify installation:
```bash
docker --version
docker-compose --version
```

### Step 4.2: Configure Environment

Same as Step 3.5 - create and edit `.env` file.

### Step 4.3: Build Docker Image

```bash
# Using helper script
chmod +x run-docker.sh
./run-docker.sh build

# Or manually
docker-compose build
```

This builds the scanner Docker image (~500MB).

---

## 5. First Scan

### Option A: Local Python

```bash
# Activate virtual environment (if not already)
source venv/bin/activate

# Run scanner
python scanner.py
```

### Option B: Docker

```bash
# Using helper script
./run-docker.sh run

# Or manually
docker-compose up onedrive-scanner
```

### What to Expect

You should see output like:

```
======================================================================
M365 ONEDRIVE SECURITY SCANNER
======================================================================
Step 1: Authenticating with Microsoft Graph API...
✓ Authentication successful

Step 2: Scanning OneDrive files...
Scanning OneDrive for: user1@domain.com
Found 42 files for user1@domain.com
Scanning OneDrive for: user2@domain.com
Found 37 files for user2@domain.com
✓ Scanned 2 users

Step 3: Analyzing file permissions and links...
✓ Analyzed 79 files

Step 4: Detecting sensitive data in filenames...
✓ Sensitive data detection complete

Step 5: Filtering results...
Filtered to 79 files with low+ risk

Step 6: Generating reports...
✓ JSON report: ./reports/onedrive_scan_20250117_143022.json
✓ CSV report: ./reports/onedrive_scan_20250117_143022.csv
✓ HTML report: ./reports/onedrive_scan_20250117_143022.html

======================================================================
ONEDRIVE SECURITY SCAN SUMMARY
======================================================================

╒═══════════════════════════╤═════════╕
│ Metric                    │   Count │
╞═══════════════════════════╪═════════╡
│ Total Files               │      79 │
│ Files with Sharing        │      23 │
│ Anyone Links (CRITICAL)   │       5 │
│ Org-Wide Links (HIGH)     │      12 │
│ Sensitive Files           │       8 │
╘═══════════════════════════╧═════════╛
```

### View Reports

Reports are saved in `./reports/` directory:

```bash
# List reports
ls -lh reports/

# View HTML report in browser
# On Linux/Mac:
open reports/onedrive_scan_*.html

# On Windows:
start reports/onedrive_scan_*.html

# View JSON
cat reports/onedrive_scan_*.json | jq

# Open CSV in Excel/LibreOffice
```

---

## 6. Scheduled Scanning

### Option A: Docker Cron

```bash
# Edit cron schedule
nano cron-schedule

# Example schedules:
# Daily at 2 AM
0 2 * * * cd /app && python scanner.py >> /app/logs/cron.log 2>&1

# Start scheduled scanner
./run-docker.sh scheduled

# View logs
docker logs -f m365-onedrive-scanner-cron
```

### Option B: System Cron (Linux/Mac)

```bash
# Edit crontab
crontab -e

# Add this line (adjust path):
0 2 * * * cd /home/user/M365-AdminIO && /home/user/M365-AdminIO/venv/bin/python scanner.py >> /home/user/M365-AdminIO/logs/cron.log 2>&1

# Save and exit
```

### Option C: Windows Task Scheduler

1. Open **Task Scheduler**
2. Click **Create Task**
3. **General Tab**:
   - Name: `OneDrive Security Scan`
   - Run whether user is logged on or not
4. **Triggers Tab**:
   - New > Daily
   - Start time: 2:00 AM
5. **Actions Tab**:
   - New > Start a program
   - Program: `C:\path\to\M365-AdminIO\venv\Scripts\python.exe`
   - Arguments: `scanner.py`
   - Start in: `C:\path\to\M365-AdminIO`
6. Click **OK**

---

## Verification Checklist

Before considering setup complete, verify:

- [ ] Azure AD app registered
- [ ] Client ID, Tenant ID, and Secret copied
- [ ] API permissions added (Files.Read.All, Sites.Read.All, User.Read.All, Reports.Read.All)
- [ ] Admin consent granted (green checkmarks)
- [ ] `.env` file created with credentials
- [ ] Python dependencies installed (or Docker image built)
- [ ] First scan completed successfully
- [ ] Reports generated (JSON, CSV, HTML)
- [ ] Can open and view HTML report
- [ ] Scheduled scanning configured (optional)

---

## Troubleshooting

### "Authentication failed"

**Check**:
1. CLIENT_ID, TENANT_ID, CLIENT_SECRET are correct in `.env`
2. Client secret hasn't expired
3. Admin consent granted
4. No typos or extra spaces in `.env`

**Test**:
```bash
# Check if .env is loaded
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('CLIENT_ID'))"
```

### "Permission denied" errors

**Fix**:
```bash
# On Linux/Mac - ensure permissions
chmod +x scanner.py
chmod +x run-docker.sh

# On Windows - run as Administrator
```

### "Module not found" errors

**Fix**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### No files found

**Check**:
1. Users have OneDrive enabled
2. Users have accessed OneDrive at least once
3. SCAN_ALL_USERS is set to `true` in `.env`
4. API permissions include Files.Read.All

### Docker issues

**Fix**:
```bash
# Check Docker is running
docker info

# Rebuild image
./run-docker.sh clean
./run-docker.sh build

# Check logs
docker logs m365-onedrive-scanner
```

---

## Next Steps

1. **Review Reports**: Check for any critical findings
2. **Customize Scanning**:
   - Scan specific users: `python scanner.py --users user@domain.com`
   - Filter by risk: `python scanner.py --min-risk high`
3. **Set Up Alerts**: Configure notifications for critical findings
4. **Schedule Regular Scans**: Use cron or Task Scheduler
5. **Integrate with SIEM**: Export JSON reports to your security tools

---

## Support

- **Documentation**: See README.md
- **Issues**: Open GitHub issue
- **Questions**: Check existing issues first

## Security Note

Keep your `.env` file secure:
- Never commit to Git (already in .gitignore)
- Restrict file permissions: `chmod 600 .env`
- Rotate secrets regularly
- Use Azure Key Vault for production
