#!/bin/bash

# One-liner WiFi Jammer Tool Installation
# Usage: curl -sSL https://raw.githubusercontent.com/your-repo/wifi-jammer/main/quick_install.sh | sudo bash

set -e

echo "🚀 Quick installing WiFi Jammer Tool..."

# Download the repository
if [ ! -d "/tmp/wifi-jammer" ]; then
    echo "📥 Downloading WiFi Jammer Tool..."
    git clone https://github.com/oyi77/wifi-jammer.git /tmp/wifi-jammer
fi

# Change to directory
cd /tmp/wifi-jammer

# Run installation
echo "🔧 Installing..."
bash install.sh

echo "✅ Quick installation completed!"
echo "Usage: sudo wifi-jammer" 