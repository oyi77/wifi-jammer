#!/usr/bin/env python3
"""
Automated macOS setup script for WiFi Jammer.
Handles installation, permission requests, and Python detection.
"""

import sys
import os
import platform
import subprocess
import time
from pathlib import Path

def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70 + "\n")

def run_command(cmd, check=True, timeout=60):
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if check and result.returncode != 0:
            print(f"⚠️  Command failed: {cmd}")
            if result.stderr:
                print(f"   Error: {result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        print(f"⚠️  Command timed out: {cmd}")
        return None

def install_dependencies(python_exe):
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    
    # Install base requirements
    print("   Installing base requirements...")
    result = run_command(f"{python_exe} -m pip install -q -r requirements.txt", check=False)
    
    # Install macOS-specific dependencies
    if platform.system() == "Darwin":
        print("   Installing macOS-specific dependencies...")
        run_command(f"{python_exe} -m pip install -q pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation", check=False)
    
    print("✅ Dependencies installed\n")

def test_wifi_access(python_exe):
    """Test if WiFi access is working with this Python."""
    try:
        script = """
from CoreWLAN import CWWiFiClient
try:
    client = CWWiFiClient.sharedWiFiClient()
    interface = client.interface()
    if interface:
        ssid = interface.ssid()
        bssid = interface.bssid()
        if ssid and bssid:
            print(f'SUCCESS:{ssid}:{bssid}')
        else:
            print('NO_PERMISSION')
    else:
        print('NO_INTERFACE')
except Exception as e:
    print(f'ERROR:{e}')
"""
        result = run_command(f'{python_exe} -c "{script}"', check=False, timeout=10)
        if result and result.stdout:
            if 'SUCCESS:' in result.stdout:
                parts = result.stdout.strip().split(':')
                return True, parts[1], parts[2]
            return False, None, None
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
            FileNotFoundError, OSError, ValueError, IndexError):
        pass
    return False, None, None

def request_location_permission(python_exe):
    """Request Location Services permission using CoreLocation."""
    print("🔔 Requesting Location Services permission...")
    print("   (A dialog should appear - please click 'Allow' or 'OK')\n")
    
    script = """
import CoreLocation
import time

location_manager = CoreLocation.CLLocationManager.alloc().init()
location_manager.requestWhenInUseAuthorization()
location_manager.startUpdatingLocation()
time.sleep(5)
location_manager.stopUpdatingLocation()
print('DIALOG_TRIGGERED')
"""
    
    try:
        result = run_command(f'{python_exe} -c "{script}"', check=False, timeout=15)
        if result and 'DIALOG_TRIGGERED' in result.stdout:
            print("✅ Permission dialog triggered")
            print("   Please click 'Allow' if a dialog appeared\n")
            return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
            FileNotFoundError, OSError, ValueError):
        pass
    
    print("⚠️  Could not trigger dialog automatically")
    return False

def find_python_with_permission():
    """Find which Python executable has Location Services permission."""
    print("🔍 Detecting Python with Location Services permission...\n")
    
    # Test common Python paths
    project_root = Path(__file__).parent.parent
    python_paths = [
        sys.executable,  # Current Python
        "/usr/bin/python3",  # System Python
        str(project_root / "venv" / "bin" / "python3"),  # Venv Python
        "/opt/homebrew/bin/python3",  # Homebrew Python
    ]
    
    for python_exe in python_paths:
        if not os.path.exists(python_exe):
            continue
        
        print(f"   Testing: {python_exe}")
        has_access, ssid, bssid = test_wifi_access(python_exe)
        
        if has_access:
            print(f"✅ Found Python with permission: {python_exe}")
            print(f"   SSID: {ssid}, BSSID: {bssid}\n")
            return python_exe
        else:
            print(f"   ❌ No permission\n")
    
    return None

def setup_macos():
    """Main setup function for macOS."""
    if platform.system() != "Darwin":
        print("❌ This script is for macOS only")
        sys.exit(1)
    
    print_header("WiFi Jammer - macOS Automated Setup")
    
    # Step 1: Install dependencies
    print_header("Step 1: Installing Dependencies")
    current_python = sys.executable
    install_dependencies(current_python)
    
    # Step 2: Check for existing permission
    print_header("Step 2: Checking Location Services Permission")
    python_with_permission = find_python_with_permission()
    
    if python_with_permission:
        print(f"✅ Permission already granted to: {python_with_permission}")
        save_python_path(python_with_permission)
        print("\n🎉 Setup complete! You can now run the scanner.")
        print(f"\n   Run with: {python_with_permission} -m wifi_jammer.cli scan")
        return
    
    # Step 3: Request permission
    print_header("Step 3: Requesting Location Services Permission")
    
    # Try with current Python first
    if request_location_permission(current_python):
        time.sleep(2)
        has_access, ssid, bssid = test_wifi_access(current_python)
        if has_access:
            print(f"✅ Permission granted to: {current_python}")
            save_python_path(current_python)
            print("\n🎉 Setup complete!")
            return
    
    # Try with system Python
    system_python = "/usr/bin/python3"
    if os.path.exists(system_python) and system_python != current_python:
        print(f"\n🔄 Trying with system Python: {system_python}")
        install_dependencies(system_python)
        if request_location_permission(system_python):
            time.sleep(2)
            has_access, ssid, bssid = test_wifi_access(system_python)
            if has_access:
                print(f"✅ Permission granted to: {system_python}")
                save_python_path(system_python)
                print("\n🎉 Setup complete!")
                return
    
    # Step 4: Manual instructions
    print_header("Manual Permission Setup Required")
    print("The permission dialog may not have appeared, or permission wasn't granted.")
    print("\n📋 Please follow these steps:")
    print("\n1. Open System Settings")
    print("2. Go to Privacy & Security → Location Services")
    print("3. Make sure Location Services is ON (toggle at top)")
    print("4. Scroll down and find 'Python' or 'python3' in the list")
    print("5. Check the box ✅ next to it")
    print("\nIf Python doesn't appear:")
    print("  - Keep System Settings open")
    print(f"  - Run: {current_python} -c \"from CoreWLAN import CWWiFiClient; CWWiFiClient.sharedWiFiClient().interface().ssid()\"")
    print("  - Wait 5-10 seconds")
    print("  - Go back to System Settings - Python should appear")
    print("  - Check the box ✅")
    print("\nAfter granting permission, run this script again to verify.")
    print("\nOr run the scanner directly - it will detect which Python has permission.")

def save_python_path(python_exe):
    """Save the Python path that has permission to a config file."""
    # Save to project root (parent of tools directory)
    config_file = Path(__file__).parent.parent / ".python_with_permission"
    try:
        with open(config_file, 'w') as f:
            f.write(python_exe)
        print(f"💾 Saved Python path to: {config_file}")
    except (IOError, OSError, PermissionError):
        pass

def get_python_with_permission():
    """Get the Python path that has permission from config file."""
    # Check in project root (parent of tools directory)
    config_file = Path(__file__).parent.parent / ".python_with_permission"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                python_exe = f.read().strip()
            if os.path.exists(python_exe):
                return python_exe
        except (IOError, OSError, ValueError, PermissionError):
            pass
    return None

if __name__ == "__main__":
    setup_macos()

