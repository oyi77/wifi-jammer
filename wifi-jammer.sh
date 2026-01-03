#!/bin/bash
# Unified WiFi Jammer wrapper script
# Cross-platform wrapper that automatically detects the best Python to use
# Handles macOS Location Services, Linux, and provides Windows guidance

set -euo pipefail  # Exit on error, undefined vars, pipe failures

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Detect operating system
detect_os() {
    case "$OSTYPE" in
        darwin*)
            echo "macos"
            ;;
        linux-gnu*|linux-musl*)
            echo "linux"
            ;;
        msys|cygwin|win32)
            echo "windows"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

OS_TYPE=$(detect_os)

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Python command exists and is usable
python_exists() {
    local python_cmd="$1"
    if [ -f "$python_cmd" ] && [ -x "$python_cmd" ]; then
        "$python_cmd" --version >/dev/null 2>&1
        return $?
    fi
    return 1
}

# On macOS, try to find Python with Location Services permission
if [ "$OS_TYPE" = "macos" ]; then
    # Try to use the Python detector utility
    PYTHON_WITH_PERMISSION=$(python3 -c "
import sys
import os
from pathlib import Path

def test_wifi_access(python_exe):
    try:
        import subprocess
        script = '''
from CoreWLAN import CWWiFiClient
try:
    client = CWWiFiClient.sharedWiFiClient()
    interface = client.interface()
    if interface:
        ssid = interface.ssid()
        bssid = interface.bssid()
        if ssid and bssid:
            print('SUCCESS')
        else:
            print('NO_PERMISSION')
    else:
        print('NO_INTERFACE')
except:
    print('ERROR')
'''
        result = subprocess.run([python_exe, '-c', script], capture_output=True, text=True, timeout=5)
        return 'SUCCESS' in result.stdout
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False

def test_dependencies(python_exe):
    """Test if Python has required dependencies installed."""
    try:
        import subprocess
        # Test core dependencies
        script = '''
try:
    import wifi_jammer
    import textual
    import rich
    import click
    import scapy
    print('HAS_DEPS')
except ImportError as e:
    print(f'NO_DEPS:{e}')
'''
        result = subprocess.run([python_exe, '-c', script], capture_output=True, text=True, timeout=5)
        return 'HAS_DEPS' in result.stdout
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False

# Check saved config first
config_file = Path('$SCRIPT_DIR') / '.python_with_permission'
if config_file.exists():
    try:
        with open(config_file, 'r') as f:
            python_exe = f.read().strip()
        if os.path.exists(python_exe) and test_wifi_access(python_exe) and test_dependencies(python_exe):
            print(python_exe)
            sys.exit(0)
    except (IOError, OSError, ValueError, PermissionError):
        pass

# Test common Python paths - prioritize system Python first
# We want Python with BOTH permission AND dependencies
python_paths = [
    '/usr/bin/python3',  # System Python (most likely to have permission)
    '/opt/homebrew/bin/python3',  # Homebrew Python
    sys.executable,  # Current Python
    str(Path('$SCRIPT_DIR') / 'venv' / 'bin' / 'python3'),  # Venv Python
]

# First pass: Find Python with BOTH permission AND dependencies (ideal)
for python_exe in python_paths:
    if os.path.exists(python_exe):
        if test_wifi_access(python_exe) and test_dependencies(python_exe):
            print(python_exe)
            sys.exit(0)

# Second pass: Find Python with permission (we can install deps later)
for python_exe in python_paths:
    if os.path.exists(python_exe):
        if test_wifi_access(python_exe):
            print(python_exe)
            sys.exit(0)

# Third pass: Find Python with dependencies (for non-scanning operations)
# Prioritize venv Python when running with sudo (likely has dependencies)
venv_python = str(Path('$SCRIPT_DIR') / 'venv' / 'bin' / 'python3')
if os.path.exists(venv_python) and test_dependencies(venv_python):
    print(venv_python)
    sys.exit(0)

for python_exe in python_paths:
    if os.path.exists(python_exe):
        if test_dependencies(python_exe):
            print(python_exe)
            sys.exit(0)

# Fallback to current Python
print(sys.executable)
" 2>/dev/null)

    if [ -n "$PYTHON_WITH_PERMISSION" ] && [ -f "$PYTHON_WITH_PERMISSION" ]; then
        # Check if this Python has dependencies
        if "$PYTHON_WITH_PERMISSION" -c "import wifi_jammer, textual, rich, click, scapy" 2>/dev/null; then
            # Preserve sudo environment when exec'ing
            exec "$PYTHON_WITH_PERMISSION" -m wifi_jammer.cli "$@"
        else
            # Python has permission but missing dependencies - try to install them
            echo "⚠️  Python with permission found but missing dependencies." >&2
            echo "   Installing dependencies to $PYTHON_WITH_PERMISSION..." >&2
            if ! "$PYTHON_WITH_PERMISSION" -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>&1 | grep -v "already satisfied"; then
                echo "❌ Failed to install dependencies. Please install manually:" >&2
                echo "   $PYTHON_WITH_PERMISSION -m pip install -r $SCRIPT_DIR/requirements.txt" >&2
                exit 1
            fi
            # Preserve sudo environment when exec'ing
            exec "$PYTHON_WITH_PERMISSION" -m wifi_jammer.cli "$@"
        fi
    else
        # No Python with permission found - use venv if available, otherwise warn
        # When running with sudo, prefer venv Python as it likely has dependencies installed
        if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
            # Check if venv Python has dependencies
            if "$SCRIPT_DIR/venv/bin/python3" -c "import wifi_jammer, textual, rich, click, scapy" 2>/dev/null; then
                echo "⚠️  Warning: No Python with Location Services permission found." >&2
                echo "   Using venv Python (has dependencies). Scanning may show redacted networks." >&2
                echo "   Run 'bash install.sh' to set up permissions on system Python." >&2
                # Preserve sudo environment when exec'ing
                exec "$SCRIPT_DIR/venv/bin/python3" -m wifi_jammer.cli "$@"
            else
                echo "⚠️  Warning: Venv Python found but missing dependencies." >&2
                echo "   Installing dependencies to venv..." >&2
                if ! "$SCRIPT_DIR/venv/bin/python3" -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>&1 | grep -v "already satisfied"; then
                    echo "❌ Failed to install dependencies. Please install manually:" >&2
                    echo "   $SCRIPT_DIR/venv/bin/python3 -m pip install -r $SCRIPT_DIR/requirements.txt" >&2
                    exit 1
                fi
                exec "$SCRIPT_DIR/venv/bin/python3" -m wifi_jammer.cli "$@"
            fi
        else
            echo "⚠️  Warning: No Python with Location Services permission found." >&2
            echo "   Using system Python. Run 'bash install.sh' to set up." >&2
            if ! command_exists python3; then
                echo "❌ Error: python3 not found in PATH" >&2
                exit 1
            fi
            # Preserve sudo environment when exec'ing
            exec python3 -m wifi_jammer.cli "$@"
        fi
    fi
elif [ "$OS_TYPE" = "linux" ]; then
    # Linux: use venv Python if available, otherwise system Python
    # Check for required commands
    if ! command_exists python3; then
        echo "❌ Error: python3 not found. Please install Python 3." >&2
        exit 1
    fi
    
    # Prefer venv Python when available
    if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
        # Check if venv Python has dependencies
        if "$SCRIPT_DIR/venv/bin/python3" -c "import wifi_jammer, textual, rich, click, scapy" 2>/dev/null; then
            exec "$SCRIPT_DIR/venv/bin/python3" -m wifi_jammer.cli "$@"
        else
            echo "Installing dependencies to venv..." >&2
            if ! "$SCRIPT_DIR/venv/bin/python3" -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>&1 | grep -v "already satisfied"; then
                echo "❌ Failed to install dependencies. Please install manually:" >&2
                echo "   $SCRIPT_DIR/venv/bin/python3 -m pip install -r $SCRIPT_DIR/requirements.txt" >&2
                exit 1
            fi
            exec "$SCRIPT_DIR/venv/bin/python3" -m wifi_jammer.cli "$@"
        fi
    else
        # Use system Python
        exec python3 -m wifi_jammer.cli "$@"
    fi
elif [ "$OS_TYPE" = "windows" ]; then
    # Windows: provide guidance (bash may be available via Git Bash or WSL)
    echo "⚠️  Windows detected. This bash script may not work on Windows." >&2
    echo "   For Windows, please use:" >&2
    echo "   1. Python directly: python -m wifi_jammer.cli" >&2
    echo "   2. Or use WSL (Windows Subsystem for Linux)" >&2
    echo "   3. Or use Git Bash if available" >&2
    echo "" >&2
    
    # Try to use python if available (may work in Git Bash)
    if command_exists python; then
        exec python -m wifi_jammer.cli "$@"
    elif command_exists python3; then
        exec python3 -m wifi_jammer.cli "$@"
    else
        echo "❌ Error: Python not found. Please install Python 3." >&2
        exit 1
    fi
else
    # Unknown OS
    echo "⚠️  Unknown operating system: $OS_TYPE" >&2
    echo "   Attempting to use system Python..." >&2
    
    if command_exists python3; then
        exec python3 -m wifi_jammer.cli "$@"
    elif command_exists python; then
        exec python -m wifi_jammer.cli "$@"
    else
        echo "❌ Error: Python not found. Please install Python 3." >&2
        exit 1
    fi
fi
