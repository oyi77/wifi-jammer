#!/bin/bash
# Install script for WiFi Jammer

set -e

echo "=========================================="
echo "WiFi Jammer Installation"
echo "=========================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Detected macOS"
    echo ""
    echo "Running macOS-specific setup (includes permission request)..."
    python3 tools/setup_macos.py
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Detected Linux"
    echo ""
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
    echo "✅ Installation complete!"
    echo ""
    echo "Run the tool with:"
    echo "  sudo python3 -m wifi_jammer.cli scan"
else
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
    echo "✅ Installation complete!"
fi
