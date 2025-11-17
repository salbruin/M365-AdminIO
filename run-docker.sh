#!/bin/bash
# Helper script to run the OneDrive scanner in Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}M365 OneDrive Security Scanner - Docker Runner${NC}"
echo "================================================"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please create a .env file based on .env.example"
    echo "See README.md for instructions"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running!${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

# Parse command line arguments
MODE=${1:-run}

case $MODE in
    build)
        echo -e "${YELLOW}Building Docker image...${NC}"
        docker-compose build
        echo -e "${GREEN}✓ Build complete${NC}"
        ;;

    run)
        echo -e "${YELLOW}Running scanner...${NC}"
        docker-compose up onedrive-scanner
        echo -e "${GREEN}✓ Scan complete${NC}"
        ;;

    scheduled)
        echo -e "${YELLOW}Starting scheduled scanner (cron)...${NC}"
        docker-compose --profile scheduled up -d onedrive-scanner-scheduled
        echo -e "${GREEN}✓ Scheduled scanner started${NC}"
        echo "View logs with: docker logs -f m365-onedrive-scanner-cron"
        ;;

    viewer)
        echo -e "${YELLOW}Starting report viewer...${NC}"
        docker-compose --profile viewer up -d report-viewer
        echo -e "${GREEN}✓ Report viewer started${NC}"
        echo "View reports at: http://localhost:8080/reports/"
        ;;

    all)
        echo -e "${YELLOW}Starting all services...${NC}"
        docker-compose --profile scheduled --profile viewer up -d
        echo -e "${GREEN}✓ All services started${NC}"
        echo "Report viewer: http://localhost:8080/reports/"
        ;;

    stop)
        echo -e "${YELLOW}Stopping all services...${NC}"
        docker-compose --profile scheduled --profile viewer down
        echo -e "${GREEN}✓ All services stopped${NC}"
        ;;

    clean)
        echo -e "${YELLOW}Cleaning up Docker resources...${NC}"
        docker-compose --profile scheduled --profile viewer down -v
        docker system prune -f
        echo -e "${GREEN}✓ Cleanup complete${NC}"
        ;;

    shell)
        echo -e "${YELLOW}Opening shell in scanner container...${NC}"
        docker-compose run --rm onedrive-scanner /bin/bash
        ;;

    security-scan)
        echo -e "${YELLOW}Running security scan with Trivy...${NC}"
        ./scripts/security-scan.sh
        echo -e "${GREEN}✓ Security scan complete${NC}"
        echo "Reports available in: ./security-reports/"
        ;;

    sbom)
        echo -e "${YELLOW}Generating SBOM...${NC}"
        ./scripts/generate-sbom.sh
        echo -e "${GREEN}✓ SBOM generation complete${NC}"
        echo "SBOM files available in: ./sbom/"
        ;;

    install-trivy)
        echo -e "${YELLOW}Installing Trivy...${NC}"
        ./scripts/install-trivy.sh
        ;;

    *)
        echo "Usage: $0 {build|run|scheduled|viewer|all|stop|clean|shell|security-scan|sbom|install-trivy}"
        echo ""
        echo "Commands:"
        echo "  build          - Build the Docker image"
        echo "  run            - Run a single scan"
        echo "  scheduled      - Start scheduled scanning (cron)"
        echo "  viewer         - Start web viewer for reports"
        echo "  all            - Start all services"
        echo "  stop           - Stop all services"
        echo "  clean          - Clean up Docker resources"
        echo "  shell          - Open shell in container"
        echo "  security-scan  - Run Trivy security scan on container"
        echo "  sbom           - Generate Software Bill of Materials"
        echo "  install-trivy  - Install Trivy scanner"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
