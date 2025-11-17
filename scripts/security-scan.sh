#!/bin/bash
# Container Security Scanning Script
# Uses Trivy for vulnerability scanning and SBOM generation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security-reports"
IMAGE_NAME="${IMAGE_NAME:-m365-adminio-onedrive-scanner}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Create reports directory
mkdir -p "$REPORTS_DIR"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Container Security Scanning${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Trivy not found. Installing...${NC}"

    # Install Trivy based on OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux installation
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update
        sudo apt-get install trivy -y
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS installation
        brew install aquasecurity/trivy/trivy
    else
        echo -e "${RED}Unsupported OS. Please install Trivy manually:${NC}"
        echo "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        exit 1
    fi
fi

echo -e "${GREEN}✓ Trivy installed${NC}"
echo ""

# Update Trivy database
echo -e "${BLUE}Updating vulnerability database...${NC}"
trivy image --download-db-only
echo -e "${GREEN}✓ Database updated${NC}"
echo ""

# Scan 1: Dockerfile
echo -e "${BLUE}[1/5] Scanning Dockerfile for misconfigurations...${NC}"
trivy config \
    --config "$PROJECT_ROOT/trivy.yaml" \
    --format table \
    --severity CRITICAL,HIGH,MEDIUM \
    "$PROJECT_ROOT/Dockerfile" \
    2>&1 | tee "$REPORTS_DIR/dockerfile-scan.txt"

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo -e "${GREEN}✓ Dockerfile scan complete - no issues found${NC}"
else
    echo -e "${YELLOW}⚠ Dockerfile scan complete - issues found (see report)${NC}"
fi
echo ""

# Scan 2: Filesystem (before Docker build)
echo -e "${BLUE}[2/5] Scanning project files for vulnerabilities...${NC}"
trivy fs \
    --config "$PROJECT_ROOT/trivy.yaml" \
    --format table \
    --severity CRITICAL,HIGH \
    --skip-dirs venv,.venv,node_modules,.git \
    "$PROJECT_ROOT" \
    2>&1 | tee "$REPORTS_DIR/filesystem-scan.txt"

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo -e "${GREEN}✓ Filesystem scan complete - no critical issues${NC}"
else
    echo -e "${YELLOW}⚠ Filesystem scan complete - issues found (see report)${NC}"
fi
echo ""

# Scan 3: Secret detection
echo -e "${BLUE}[3/5] Scanning for exposed secrets...${NC}"
trivy fs \
    --scanners secret \
    --format table \
    --skip-dirs venv,.venv,node_modules,.git \
    "$PROJECT_ROOT" \
    2>&1 | tee "$REPORTS_DIR/secret-scan.txt"

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo -e "${GREEN}✓ Secret scan complete - no secrets found${NC}"
else
    echo -e "${RED}✗ SECRET SCAN FAILED - Secrets detected!${NC}"
    echo -e "${RED}  Review: $REPORTS_DIR/secret-scan.txt${NC}"
fi
echo ""

# Build Docker image if not exists
if ! docker image inspect "$IMAGE_NAME:$IMAGE_TAG" &> /dev/null; then
    echo -e "${BLUE}Building Docker image...${NC}"
    cd "$PROJECT_ROOT"
    docker build -t "$IMAGE_NAME:$IMAGE_TAG" .
    echo -e "${GREEN}✓ Image built${NC}"
    echo ""
fi

# Scan 4: Container image vulnerabilities
echo -e "${BLUE}[4/5] Scanning Docker image for vulnerabilities...${NC}"
trivy image \
    --config "$PROJECT_ROOT/trivy.yaml" \
    --format table \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    "$IMAGE_NAME:$IMAGE_TAG" \
    2>&1 | tee "$REPORTS_DIR/image-scan.txt"

# Also generate JSON report for automation
trivy image \
    --format json \
    --output "$REPORTS_DIR/image-scan.json" \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > /dev/null 2>&1

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo -e "${GREEN}✓ Image scan complete - no critical issues${NC}"
else
    echo -e "${YELLOW}⚠ Image scan complete - vulnerabilities found${NC}"
fi
echo ""

# Scan 5: Generate SBOM
echo -e "${BLUE}[5/5] Generating Software Bill of Materials (SBOM)...${NC}"

# SBOM in CycloneDX format (JSON)
trivy image \
    --format cyclonedx \
    --output "$REPORTS_DIR/sbom-cyclonedx.json" \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > /dev/null 2>&1

echo -e "${GREEN}✓ SBOM (CycloneDX JSON): $REPORTS_DIR/sbom-cyclonedx.json${NC}"

# SBOM in SPDX format
trivy image \
    --format spdx-json \
    --output "$REPORTS_DIR/sbom-spdx.json" \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > /dev/null 2>&1

echo -e "${GREEN}✓ SBOM (SPDX JSON): $REPORTS_DIR/sbom-spdx.json${NC}"

# SBOM in table format for human reading
trivy image \
    --format table \
    --list-all-pkgs \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > "$REPORTS_DIR/sbom-packages.txt" 2>&1

echo -e "${GREEN}✓ SBOM (Package list): $REPORTS_DIR/sbom-packages.txt${NC}"
echo ""

# Generate HTML reports
echo -e "${BLUE}Generating HTML reports...${NC}"

trivy image \
    --format template \
    --template "@contrib/html.tpl" \
    --output "$REPORTS_DIR/image-scan.html" \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > /dev/null 2>&1

echo -e "${GREEN}✓ HTML Report: $REPORTS_DIR/image-scan.html${NC}"
echo ""

# Summary
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Security Scan Summary${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "Image scanned: ${GREEN}$IMAGE_NAME:$IMAGE_TAG${NC}"
echo -e "Reports directory: ${GREEN}$REPORTS_DIR${NC}"
echo ""
echo "Generated reports:"
echo "  1. Dockerfile scan:      $REPORTS_DIR/dockerfile-scan.txt"
echo "  2. Filesystem scan:      $REPORTS_DIR/filesystem-scan.txt"
echo "  3. Secret scan:          $REPORTS_DIR/secret-scan.txt"
echo "  4. Image scan (table):   $REPORTS_DIR/image-scan.txt"
echo "  5. Image scan (JSON):    $REPORTS_DIR/image-scan.json"
echo "  6. Image scan (HTML):    $REPORTS_DIR/image-scan.html"
echo "  7. SBOM (CycloneDX):     $REPORTS_DIR/sbom-cyclonedx.json"
echo "  8. SBOM (SPDX):          $REPORTS_DIR/sbom-spdx.json"
echo "  9. SBOM (Package list):  $REPORTS_DIR/sbom-packages.txt"
echo ""

# Parse results
CRITICAL_COUNT=$(grep -c "CRITICAL" "$REPORTS_DIR/image-scan.txt" || echo "0")
HIGH_COUNT=$(grep -c "HIGH" "$REPORTS_DIR/image-scan.txt" || echo "0")

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ CRITICAL vulnerabilities found: $CRITICAL_COUNT${NC}"
    exit 1
elif [ "$HIGH_COUNT" -gt 5 ]; then
    echo -e "${YELLOW}⚠ HIGH vulnerabilities found: $HIGH_COUNT${NC}"
    echo -e "${YELLOW}  Consider reviewing and updating dependencies${NC}"
    exit 0
else
    echo -e "${GREEN}✓ Security scan completed successfully${NC}"
    exit 0
fi
