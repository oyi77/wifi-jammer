#!/bin/bash
# Quick install script for WiFi Jammer

set -e

echo "=========================================="
echo "WiFi Jammer Quick Install"
echo "=========================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 macOS detected - running automated setup..."
    python3 tools/setup_macos.py
else
    echo "📦 Installing dependencies..."
    pip3 install -q -r requirements.txt
    echo "✅ Done!"
    echo ""
    echo "Run: sudo python3 -m wifi_jammer.cli scan"
fi
