#!/bin/bash
# Generate Software Bill of Materials (SBOM)
# Supports multiple formats: CycloneDX, SPDX, SWID

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SBOM_DIR="$PROJECT_ROOT/sbom"
IMAGE_NAME="${IMAGE_NAME:-m365-adminio-onedrive-scanner}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create SBOM directory
mkdir -p "$SBOM_DIR"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}SBOM Generation${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "Error: Trivy is not installed."
    echo "Please run: ./scripts/security-scan.sh"
    echo "Or install manually: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Build image if needed
if ! docker image inspect "$IMAGE_NAME:$IMAGE_TAG" &> /dev/null; then
    echo -e "${BLUE}Building Docker image...${NC}"
    cd "$PROJECT_ROOT"
    docker build -t "$IMAGE_NAME:$IMAGE_TAG" .
    echo ""
fi

echo -e "${BLUE}Generating SBOM for: $IMAGE_NAME:$IMAGE_TAG${NC}"
echo ""

# 1. CycloneDX JSON (industry standard for dependency tracking)
echo -e "${BLUE}[1/5] Generating CycloneDX JSON...${NC}"
trivy image \
    --format cyclonedx \
    --output "$SBOM_DIR/sbom_${TIMESTAMP}_cyclonedx.json" \
    "$IMAGE_NAME:$IMAGE_TAG"
echo -e "${GREEN}✓ $SBOM_DIR/sbom_${TIMESTAMP}_cyclonedx.json${NC}"

# 2. SPDX JSON (Linux Foundation standard)
echo -e "${BLUE}[2/5] Generating SPDX JSON...${NC}"
trivy image \
    --format spdx-json \
    --output "$SBOM_DIR/sbom_${TIMESTAMP}_spdx.json" \
    "$IMAGE_NAME:$IMAGE_TAG"
echo -e "${GREEN}✓ $SBOM_DIR/sbom_${TIMESTAMP}_spdx.json${NC}"

# 3. Human-readable table
echo -e "${BLUE}[3/5] Generating package list (human-readable)...${NC}"
trivy image \
    --format table \
    --list-all-pkgs \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > "$SBOM_DIR/sbom_${TIMESTAMP}_packages.txt"
echo -e "${GREEN}✓ $SBOM_DIR/sbom_${TIMESTAMP}_packages.txt${NC}"

# 4. JSON with all details
echo -e "${BLUE}[4/5] Generating detailed JSON...${NC}"
trivy image \
    --format json \
    --list-all-pkgs \
    --output "$SBOM_DIR/sbom_${TIMESTAMP}_detailed.json" \
    "$IMAGE_NAME:$IMAGE_TAG"
echo -e "${GREEN}✓ $SBOM_DIR/sbom_${TIMESTAMP}_detailed.json${NC}"

# 5. License report
echo -e "${BLUE}[5/5] Generating license report...${NC}"
trivy image \
    --scanners license \
    --format table \
    "$IMAGE_NAME:$IMAGE_TAG" \
    > "$SBOM_DIR/licenses_${TIMESTAMP}.txt"
echo -e "${GREEN}✓ $SBOM_DIR/licenses_${TIMESTAMP}.txt${NC}"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}SBOM Generation Complete${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Generated files in: $SBOM_DIR"
echo ""
echo "  CycloneDX (JSON):  sbom_${TIMESTAMP}_cyclonedx.json"
echo "  SPDX (JSON):       sbom_${TIMESTAMP}_spdx.json"
echo "  Package List:      sbom_${TIMESTAMP}_packages.txt"
echo "  Detailed JSON:     sbom_${TIMESTAMP}_detailed.json"
echo "  Licenses:          licenses_${TIMESTAMP}.txt"
echo ""
echo "Use CycloneDX or SPDX formats for:"
echo "  - Supply chain security tools"
echo "  - Dependency tracking systems"
echo "  - Compliance reporting"
echo "  - Vulnerability management platforms"
echo ""
