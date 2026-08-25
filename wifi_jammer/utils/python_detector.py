"""
Utility to detect and use the Python executable with Location Services permission on macOS.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
from typing import Optional


def test_wifi_access(python_exe: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Test if WiFi access is working with this Python executable.

    Returns:
        (has_access, ssid, bssid) tuple
    """
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
except ImportError:
    print('NO_COREWLAN')
except Exception as e:
    print(f'ERROR:{e}')
"""
        result = subprocess.run(
            [python_exe, "-c", script], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout:
            if "SUCCESS:" in result.stdout:
                parts = result.stdout.strip().split(":")
                if len(parts) >= 3:
                    return True, parts[1], parts[2]
    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        FileNotFoundError,
        OSError,
        ValueError,
        IndexError,
    ):
        pass
    return False, None, None


def test_dependencies(python_exe: str) -> bool:
    """Test if Python has required dependencies installed."""
    try:
        script = """
try:
    import wifi_jammer
    import textual
    import rich
    import click
    import scapy
    print('HAS_DEPS')
except ImportError:
    print('NO_DEPS')
"""
        result = subprocess.run(
            [python_exe, "-c", script], capture_output=True, text=True, timeout=10
        )
        return "HAS_DEPS" in result.stdout
    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        FileNotFoundError,
        OSError,
    ):
        return False


def find_python_with_permission() -> Optional[str]:
    """Find which Python executable has Location Services permission.

    Prioritizes Python with both permission AND dependencies.

    Returns:
        Path to Python executable with permission, or None if not found
    """
    if platform.system() != "Darwin":
        return sys.executable  # On non-macOS, just use current Python

    # Check saved Python path first (in project root)
    config_dir = Path.home() / ".config" / "wifi_jammer"
    config_file = config_dir / "python_with_permission"
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                python_exe = f.read().strip()
            if os.path.exists(python_exe):
                has_access, _, _ = test_wifi_access(python_exe)
                has_deps = test_dependencies(python_exe)
                if has_access and has_deps:
                    return python_exe
        except (IOError, OSError, ValueError, PermissionError):
            pass

    # Test common Python paths - prioritize system Python first
    python_paths = [
        "/usr/bin/python3",  # System Python (prioritize - most likely to have permission)
        "/opt/homebrew/bin/python3",  # Homebrew Python
        sys.executable,  # Current Python
        str(
            Path(__file__).parent.parent.parent / "venv" / "bin" / "python3"
        ),  # Venv Python
    ]

    # First pass: Find Python with BOTH permission AND dependencies (ideal)
    for python_exe in python_paths:
        if not os.path.exists(python_exe):
            continue

        has_access, _, _ = test_wifi_access(python_exe)
        has_deps = test_dependencies(python_exe)
        if has_access and has_deps:
            # Save for future use
            try:
                config_dir.mkdir(parents=True, exist_ok=True)
                with open(config_file, "w") as f:
                    f.write(python_exe)
            except (IOError, OSError, PermissionError):
                pass
            return python_exe

    # Second pass: Find Python with permission (dependencies can be installed)
    for python_exe in python_paths:
        if not os.path.exists(python_exe):
            continue

        has_access, _, _ = test_wifi_access(python_exe)
        if has_access:
            return python_exe

    return None


def get_best_python() -> str:
    """Get the best Python executable to use.

    On macOS, returns the Python with Location Services permission if available.
    Otherwise returns the current Python.
    """
    if platform.system() == "Darwin":
        python_with_permission = find_python_with_permission()
        if python_with_permission:
            return python_with_permission

    return sys.executable
