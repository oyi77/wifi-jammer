#!/bin/bash

# WiFi Jammer Tool - Installation Script
# By Paijo

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    WiFi Jammer Tool                          ║"
echo "║              Advanced WiFi Jamming Utility                   ║"
echo "║                    By Paijo - v1.0.0                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "🔍 Detected OS: $OS"
echo ""

# Update package lists
echo "📦 Updating package lists..."
if [[ "$OS" == "linux" ]]; then
    apt-get update -qq
elif [[ "$OS" == "macos" ]]; then
    brew update -q
fi

# Install system dependencies
echo "📦 Installing system dependencies..."

if [[ "$OS" == "linux" ]]; then
    # Ubuntu/Debian
    apt-get install -y \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        libpcap-dev \
        libssl-dev \
        wireless-tools \
        iwconfig \
        aircrack-ng \
        git
elif [[ "$OS" == "macos" ]]; then
    # macOS
    if ! command -v brew &> /dev/null; then
        echo "🍺 Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install \
        python3 \
        libpcap \
        wireless-tools \
        aircrack-ng \
        git
fi

echo "✅ System dependencies installed"
echo ""

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "✅ Python dependencies installed"
echo ""

# Install the tool
echo "🔧 Installing WiFi Jammer Tool..."
pip3 install -e .

echo "✅ WiFi Jammer Tool installed successfully!"
echo ""

# Create symlink for easy access
if [[ "$OS" == "linux" ]]; then
    ln -sf $(which wifi-jammer) /usr/local/bin/wifi-jammer
elif [[ "$OS" == "macos" ]]; then
    ln -sf $(which wifi-jammer) /usr/local/bin/wifi-jammer
fi

echo "🔗 Created symlink: /usr/local/bin/wifi-jammer"
echo ""

# Set permissions
chmod +x /usr/local/bin/wifi-jammer

echo "🎉 Installation completed successfully!"
echo ""
echo "📋 Usage:"
echo "   sudo wifi-jammer                    # Interactive mode"
echo "   sudo wifi-jammer --scan-only        # Only scan networks"
echo "   sudo wifi-jammer --help             # Show help"
echo ""
echo "⚠️  WARNING: This tool is for educational purposes only!"
echo "   Use responsibly and only on networks you own or have permission to test."
echo ""
echo "🔧 Troubleshooting:"
echo "   - Make sure your wireless interface supports monitor mode"
echo "   - Some interfaces may require additional drivers"
echo "   - Run 'iwconfig' to check available interfaces"
echo "" 