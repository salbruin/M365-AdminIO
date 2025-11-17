# Security

## Container Security Scanning

This project includes comprehensive security scanning using [Trivy](https://trivy.dev/) to ensure the Docker container is free from known vulnerabilities.

### Quick Start

```bash
# Install Trivy
./run-docker.sh install-trivy

# Run full security scan
./run-docker.sh security-scan

# Generate SBOM only
./run-docker.sh sbom
```

## Security Scanning Features

### 1. Vulnerability Scanning

Scans the Docker image for:
- OS package vulnerabilities (Debian/Alpine packages)
- Python package vulnerabilities (from requirements.txt)
- Known CVEs with severity ratings (CRITICAL, HIGH, MEDIUM, LOW)

**Run scan:**
```bash
./scripts/security-scan.sh
```

**Reports generated:**
- `security-reports/image-scan.txt` - Human-readable table
- `security-reports/image-scan.json` - Machine-readable JSON
- `security-reports/image-scan.html` - Visual HTML report

### 2. Software Bill of Materials (SBOM)

Generates comprehensive inventory of all software components:

**Formats:**
- **CycloneDX JSON** - Industry standard for dependency tracking
- **SPDX JSON** - Linux Foundation standard
- **Human-readable** - Package list with versions

**Generate SBOM:**
```bash
./scripts/generate-sbom.sh
```

**Use cases:**
- Supply chain security
- License compliance
- Vulnerability tracking
- Dependency management

**Reports generated:**
- `sbom/sbom_TIMESTAMP_cyclonedx.json` - CycloneDX format
- `sbom/sbom_TIMESTAMP_spdx.json` - SPDX format
- `sbom/sbom_TIMESTAMP_packages.txt` - Package list
- `sbom/licenses_TIMESTAMP.txt` - License report

### 3. Configuration Scanning

Scans Dockerfile and configuration files for:
- Security misconfigurations
- Best practice violations
- Hardcoded secrets

### 4. Secret Detection

Scans all files for accidentally committed secrets:
- API keys
- Passwords
- Tokens
- Private keys
- Credentials

## Automated Scanning (CI/CD)

### GitHub Actions

Automated security scans run on:
- Every push to main/develop branches
- Every pull request
- Weekly schedule (Monday 2 AM UTC)
- Manual workflow dispatch

**Workflows:**
- Container vulnerability scanning
- SBOM generation
- Dockerfile security checks
- Secret scanning
- Python dependency scanning

**View results:**
- GitHub Security tab: Code scanning alerts
- Actions tab: Workflow artifacts

### Local CI Simulation

```bash
# Build and scan like CI
docker build -t m365-adminio-onedrive-scanner:test .
./scripts/security-scan.sh
```

## Security Reports

### Report Locations

```
security-reports/
├── dockerfile-scan.txt       # Dockerfile misconfigurations
├── filesystem-scan.txt       # Source code vulnerabilities
├── secret-scan.txt           # Detected secrets
├── image-scan.txt            # Container vulnerabilities (table)
├── image-scan.json           # Container vulnerabilities (JSON)
└── image-scan.html           # Container vulnerabilities (HTML)

sbom/
├── sbom_TIMESTAMP_cyclonedx.json  # CycloneDX SBOM
├── sbom_TIMESTAMP_spdx.json       # SPDX SBOM
├── sbom_TIMESTAMP_packages.txt    # Package list
├── sbom_TIMESTAMP_detailed.json   # Detailed component info
└── licenses_TIMESTAMP.txt         # License report
```

### Report Formats

**Table Format** - Quick overview in terminal
```
┌───────────────────┬──────────────┬──────────┬───────────┐
│ Library           │ Vulnerability│ Severity │ Status    │
├───────────────────┼──────────────┼──────────┼───────────┤
│ requests          │ CVE-2024-1234│ HIGH     │ fixed     │
└───────────────────┴──────────────┴──────────┴───────────┘
```

**JSON Format** - Automation and integration
```json
{
  "Results": [
    {
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1234",
          "Severity": "HIGH",
          "PkgName": "requests",
          "InstalledVersion": "2.31.0",
          "FixedVersion": "2.32.0"
        }
      ]
    }
  ]
}
```

**HTML Format** - Visual reporting
- Interactive tables
- Severity filtering
- CVE links
- Fix recommendations

## Integration with Security Tools

### SIEM Integration

Export scan results to your SIEM:

```bash
# Generate JSON report
./scripts/security-scan.sh

# Send to SIEM (example)
curl -X POST https://siem.example.com/api/events \
  -H "Content-Type: application/json" \
  -d @security-reports/image-scan.json
```

### Dependency Track

Upload SBOM to Dependency Track for continuous monitoring:

```bash
# Generate CycloneDX SBOM
./scripts/generate-sbom.sh

# Upload to Dependency Track
curl -X PUT "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @sbom/sbom_*_cyclonedx.json
```

### Vulnerability Databases

Trivy uses multiple databases:
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- OS-specific databases (Debian, Alpine, etc.)
- Language-specific databases (PyPI, npm, etc.)

## Handling Vulnerabilities

### Severity Levels

- **CRITICAL** - Immediate action required, exploit available
- **HIGH** - High priority, fix ASAP
- **MEDIUM** - Moderate risk, plan remediation
- **LOW** - Low risk, fix when convenient

### Remediation Workflow

1. **Review Report**
   ```bash
   open security-reports/image-scan.html
   ```

2. **Identify Fixes**
   - Check if updated versions available
   - Review CVE details and impact
   - Assess applicability to your usage

3. **Update Dependencies**
   ```bash
   # Update Python packages
   pip install --upgrade package-name
   pip freeze > requirements.txt
   ```

4. **Rebuild and Rescan**
   ```bash
   docker build -t m365-adminio-onedrive-scanner:latest .
   ./scripts/security-scan.sh
   ```

5. **Verify Fix**
   - Check that vulnerability no longer appears
   - Test functionality still works

### Ignoring False Positives

If a vulnerability doesn't apply to your use case:

1. Add to `.trivyignore`:
   ```
   # CVE-2024-1234 - Not applicable, we don't use the affected feature
   CVE-2024-1234
   ```

2. Document why it's ignored
3. Review periodically

## Security Best Practices

### Build-Time Security

✅ **DO:**
- Use official base images
- Pin specific versions in requirements.txt
- Run security scans before deployment
- Review dependencies regularly
- Keep base images updated

❌ **DON'T:**
- Use `latest` tags in production
- Include development tools in production images
- Commit secrets to Git
- Ignore security warnings

### Runtime Security

✅ **DO:**
- Run containers as non-root user
- Use read-only file systems where possible
- Limit container capabilities
- Monitor container behavior
- Rotate credentials regularly

❌ **DON'T:**
- Run containers with `--privileged`
- Mount sensitive host directories
- Use default credentials
- Expose unnecessary ports

### Supply Chain Security

✅ **DO:**
- Generate and maintain SBOM
- Verify package signatures when possible
- Use dependency lock files
- Monitor for new vulnerabilities
- Track all dependencies

❌ **DON'T:**
- Install packages from untrusted sources
- Skip dependency updates
- Ignore transitive dependencies

## Compliance and Auditing

### Generate Compliance Reports

```bash
# Full security audit
./scripts/security-scan.sh

# SBOM for compliance
./scripts/generate-sbom.sh

# Archive reports
tar -czf security-audit-$(date +%Y%m%d).tar.gz \
  security-reports/ sbom/
```

### Periodic Reviews

**Weekly:**
- Review GitHub Security alerts
- Check for new vulnerabilities

**Monthly:**
- Generate fresh SBOM
- Audit dependencies
- Update vulnerable packages

**Quarterly:**
- Full security assessment
- Review security policies
- Update documentation

## Troubleshooting

### Scan Fails

**Issue:** `trivy: command not found`

**Solution:**
```bash
./run-docker.sh install-trivy
```

**Issue:** Database download fails

**Solution:**
```bash
trivy image --download-db-only
```

**Issue:** Rate limiting from GitHub

**Solution:**
```bash
export GITHUB_TOKEN=your_token
trivy image --download-db-only
```

### False Positives

Some vulnerabilities may not apply:
- Check if affected code path is used
- Review CVE details and CVSS score
- Consider environment-specific mitigations
- Add to `.trivyignore` if justified

### High Vulnerability Count

Don't panic! Many are false positives or low risk:
1. Sort by severity (CRITICAL first)
2. Check if fixes available
3. Assess actual risk to your deployment
4. Create remediation plan

## Resources

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [NIST NVD](https://nvd.nist.gov/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email: security@example.com (replace with your contact)
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.
