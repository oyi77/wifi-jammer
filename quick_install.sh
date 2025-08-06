#!/bin/bash

# One-liner WiFi Jammer Tool Installation
# Usage: curl -sSL https://raw.githubusercontent.com/oyi77/wifi-jammer/main/quick_install.sh | bash

set -e

echo "🚀 Quick installing WiFi Jammer Tool..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

# Download the repository
if [ ! -d "/tmp/wifi-jammer" ]; then
    echo "📥 Downloading WiFi Jammer Tool..."
    git clone https://github.com/oyi77/wifi-jammer.git /tmp/wifi-jammer
fi

# Change to directory
cd /tmp/wifi-jammer

# Run installation based on OS
echo "🔧 Installing for $OS..."

if [[ "$OS" == "macos" ]]; then
    # macOS - run without sudo first, then with sudo for system parts
    echo "📦 Installing Python dependencies..."
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    python3 -m pip install -e .
    
    echo "🔧 Installing system dependencies (requires sudo)..."
    if ! command -v brew &> /dev/null; then
        echo "🍺 Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install python3 libpcap aircrack-ng git
    
    echo "🔗 Creating symlink (requires sudo)..."
    WIFI_JAMMER_PATH=$(python3 -c "import sys; print(sys.executable.replace('python3', 'wifi-jammer'))")
    if [[ -f "$WIFI_JAMMER_PATH" ]]; then
        sudo ln -sf "$WIFI_JAMMER_PATH" /usr/local/bin/wifi-jammer
        sudo chmod +x /usr/local/bin/wifi-jammer
    fi
    
elif [[ "$OS" == "linux" ]]; then
    # Linux - run installation script
    bash install.sh
    
elif [[ "$OS" == "windows" ]]; then
    # Windows - manual installation
    echo "⚠️  Windows installation requires manual setup:"
    echo "   1. Install Python 3.8+ from https://python.org"
    echo "   2. Install Visual Studio Build Tools"
    echo "   3. Install WinPcap or Npcap"
    echo ""
    echo "📦 Installing Python dependencies..."
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    python -m pip install -e .
    
    echo "🔗 Creating batch file..."
    WIFI_JAMMER_BAT="wifi-jammer.bat"
    echo "@echo off" > "$WIFI_JAMMER_BAT"
    echo "python -m wifi_jammer.cli %*" >> "$WIFI_JAMMER_BAT"
    echo "✅ Created: $WIFI_JAMMER_BAT"
fi

echo "✅ Quick installation completed!"
echo ""
echo "📋 Usage:"
if [[ "$OS" == "windows" ]]; then
    echo "   wifi-jammer.bat                    # Interactive mode"
    echo "   wifi-jammer.bat --scan-only        # Only scan networks"
    echo "   wifi-jammer.bat --help             # Show help"
else
    echo "   sudo wifi-jammer                    # Interactive mode"
    echo "   sudo wifi-jammer --scan-only        # Only scan networks"
    echo "   sudo wifi-jammer --help             # Show help"
fi
echo ""
echo "⚠️  WARNING: This tool is for educational purposes only!" 