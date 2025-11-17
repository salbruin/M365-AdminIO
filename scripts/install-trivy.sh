#!/bin/bash
# Install Trivy security scanner

set -e

echo "Installing Trivy..."

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux installation
    echo "Detected Linux system"

    # Check if running in Ubuntu/Debian
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update
        sudo apt-get install -y trivy
    # Check if running in RHEL/CentOS/Fedora
    elif command -v yum &> /dev/null; then
        sudo rpm --import https://aquasecurity.github.io/trivy-repo/rpm/public.key
        sudo tee /etc/yum.repos.d/trivy.repo <<'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
enabled=1
gpgcheck=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
        sudo yum install -y trivy
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi

elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS installation
    echo "Detected macOS"

    if command -v brew &> /dev/null; then
        brew install aquasecurity/trivy/trivy
    else
        echo "Homebrew not found. Please install Homebrew first:"
        echo "https://brew.sh"
        exit 1
    fi

else
    echo "Unsupported operating system: $OSTYPE"
    echo ""
    echo "Please install Trivy manually:"
    echo "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Verify installation
if command -v trivy &> /dev/null; then
    echo ""
    echo "✓ Trivy installed successfully!"
    echo ""
    trivy --version
    echo ""
    echo "Next steps:"
    echo "  1. Run security scan: ./scripts/security-scan.sh"
    echo "  2. Generate SBOM: ./scripts/generate-sbom.sh"
else
    echo "✗ Installation failed"
    exit 1
fi
