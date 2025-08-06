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

echo "🔍 Detected OS: $OS"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Python dependencies
install_python_deps() {
    echo "🐍 Installing Python dependencies..."
    
    # Check if pip3 exists
    if ! command_exists pip3; then
        echo "❌ pip3 not found. Installing Python first..."
        if [[ "$OS" == "linux" ]]; then
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip
        elif [[ "$OS" == "macos" ]]; then
            if ! command_exists brew; then
                echo "🍺 Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install python3
        elif [[ "$OS" == "windows" ]]; then
            echo "❌ Please install Python 3.8+ from https://python.org"
            exit 1
        fi
    fi
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install requirements
    python3 -m pip install -r requirements.txt
    
    echo "✅ Python dependencies installed"
}

# Function to install system dependencies
install_system_deps() {
    echo "📦 Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        # Linux - Ubuntu/Debian
        if command_exists apt-get; then
            sudo apt-get update -qq
            sudo apt-get install -y \
                python3-dev \
                build-essential \
                libpcap-dev \
                libssl-dev \
                wireless-tools \
                aircrack-ng \
                git
        elif command_exists yum; then
            # CentOS/RHEL
            sudo yum install -y \
                python3-devel \
                gcc \
                libpcap-devel \
                openssl-devel \
                wireless-tools \
                aircrack-ng \
                git
        elif command_exists pacman; then
            # Arch Linux
            sudo pacman -S --noconfirm \
                python-pip \
                base-devel \
                libpcap \
                openssl \
                wireless_tools \
                aircrack-ng \
                git
        else
            echo "⚠️  Unsupported Linux distribution. Please install dependencies manually."
        fi
        
    elif [[ "$OS" == "macos" ]]; then
        # macOS
        if ! command_exists brew; then
            echo "🍺 Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        # Install Homebrew packages
        brew install \
            python3 \
            libpcap \
            aircrack-ng \
            git
        
        echo "⚠️  Note: Some wireless tools may not be available on macOS"
        
    elif [[ "$OS" == "windows" ]]; then
        # Windows
        echo "⚠️  Windows installation requires manual setup:"
        echo "   1. Install Python 3.8+ from https://python.org"
        echo "   2. Install Visual Studio Build Tools"
        echo "   3. Install WinPcap or Npcap"
        echo "   4. Some features may be limited on Windows"
        echo ""
        echo "📦 Installing Python dependencies only..."
        return 0
    fi
    
    echo "✅ System dependencies installed"
}

# Function to install the tool
install_tool() {
    echo "🔧 Installing WiFi Jammer Tool..."
    
    # Install in development mode
    python3 -m pip install -e .
    
    echo "✅ WiFi Jammer Tool installed successfully!"
}

# Function to create symlink
create_symlink() {
    echo "🔗 Creating symlink..."
    
    if [[ "$OS" == "windows" ]]; then
        # Windows - create batch file instead of symlink
        WIFI_JAMMER_BAT="/usr/local/bin/wifi-jammer.bat"
        echo "@echo off" > "$WIFI_JAMMER_BAT"
        echo "python -m wifi_jammer.cli %*" >> "$WIFI_JAMMER_BAT"
        chmod +x "$WIFI_JAMMER_BAT"
        echo "✅ Created: $WIFI_JAMMER_BAT"
        echo "   Usage: wifi-jammer.bat"
    else
        # Linux/macOS - create symlink
        WIFI_JAMMER_PATH=$(python3 -c "import sys; print(sys.executable.replace('python3', 'wifi-jammer'))")
        
        if [[ -f "$WIFI_JAMMER_PATH" ]]; then
            sudo ln -sf "$WIFI_JAMMER_PATH" /usr/local/bin/wifi-jammer
            sudo chmod +x /usr/local/bin/wifi-jammer
            echo "✅ Created symlink: /usr/local/bin/wifi-jammer"
        else
            echo "⚠️  Could not create symlink. You can run with:"
            echo "   python3 -m wifi_jammer.cli"
        fi
    fi
}

# Function to check wireless interface support
check_wireless_support() {
    echo "🔍 Checking wireless interface support..."
    
    if [[ "$OS" == "windows" ]]; then
        echo "⚠️  Wireless interface support limited on Windows"
        echo "   Some features may not work properly"
    elif [[ "$OS" == "macos" ]]; then
        echo "⚠️  macOS has limited wireless interface support"
        echo "   Some features may require additional setup"
    else
        # Linux
        if command_exists iwconfig; then
            echo "✅ Wireless tools available"
        else
            echo "⚠️  Wireless tools not found. Some features may not work."
        fi
    fi
}

# Function to check root privileges
check_root() {
    if [[ "$OS" == "linux" ]]; then
        if [[ $EUID -ne 0 ]]; then
            echo "⚠️  Some features require root privileges on Linux"
            echo "   Run with sudo for full functionality"
        fi
    elif [[ "$OS" == "macos" ]]; then
        echo "⚠️  Some features require root privileges on macOS"
        echo "   Run with sudo for full functionality"
    elif [[ "$OS" == "windows" ]]; then
        echo "⚠️  Some features require administrator privileges on Windows"
        echo "   Run as administrator for full functionality"
    fi
}

# Main installation process
main() {
    echo "🚀 Starting installation..."
    echo ""
    
    # Check root privileges
    check_root
    echo ""
    
    # Install system dependencies
    install_system_deps
    echo ""
    
    # Install Python dependencies
    install_python_deps
    echo ""
    
    # Install the tool
    install_tool
    echo ""
    
    # Create symlink
    create_symlink
    echo ""
    
    # Check wireless support
    check_wireless_support
    echo ""
    
    echo "🎉 Installation completed successfully!"
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
    echo "   Use responsibly and only on networks you own or have permission to test."
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   - Make sure your wireless interface supports monitor mode"
    echo "   - Some interfaces may require additional drivers"
    if [[ "$OS" != "windows" ]]; then
        echo "   - Run 'iwconfig' to check available interfaces"
    fi
    echo ""
}

# Run main function
main "$@" 