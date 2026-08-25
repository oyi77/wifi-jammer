"""
Platform utilities for cross-platform compatibility.
Centralizes platform detection, command availability checking, and platform-specific utilities.
"""

import platform
import shutil
import os
import sys
import re
import subprocess
from typing import Optional, List, Tuple, Dict
from enum import Enum


class PlatformType(Enum):
    """Supported platform types."""

    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


# Cached platform type to avoid repeated system calls
_platform_type: Optional[PlatformType] = None


def get_platform_type() -> PlatformType:
    """Get the current platform type (cached).

    Returns:
        PlatformType enum value for the current platform
    """
    global _platform_type
    if _platform_type is None:
        system = platform.system().lower()
        if system == "linux":
            _platform_type = PlatformType.LINUX
        elif system == "darwin":
            _platform_type = PlatformType.MACOS
        elif system == "windows":
            _platform_type = PlatformType.WINDOWS
        else:
            _platform_type = PlatformType.UNKNOWN
    return _platform_type


def is_linux() -> bool:
    """Check if running on Linux."""
    return get_platform_type() == PlatformType.LINUX


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_platform_type() == PlatformType.MACOS


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform_type() == PlatformType.WINDOWS


def is_unix_like() -> bool:
    """Check if running on Unix-like system (Linux or macOS)."""
    return is_linux() or is_macos()


def check_command_available(command: str) -> bool:
    """Check if a command is available in the system PATH.

    Args:
        command: Command name to check

    Returns:
        True if command is available, False otherwise
    """
    return shutil.which(command) is not None


def check_commands_available(commands: List[str]) -> Tuple[List[str], List[str]]:
    """Check multiple commands for availability.

    Args:
        commands: List of command names to check

    Returns:
        Tuple of (available_commands, missing_commands)
    """
    available: List[str] = []
    missing: List[str] = []
    for cmd in commands:
        if check_command_available(cmd):
            available.append(cmd)
        else:
            missing.append(cmd)
    return available, missing


def get_platform_specific_commands() -> Dict[str, List[str]]:
    """Get platform-specific commands that should be available.

    Returns:
        Dictionary mapping command categories to expected commands
    """
    commands: Dict[str, List[str]] = {
        "network_interface": [],
        "wireless": [],
        "scanning": [],
    }

    if is_linux():
        commands["network_interface"] = ["ip", "iwconfig", "iw"]
        commands["wireless"] = ["iwconfig", "iw"]
        commands["scanning"] = ["iwlist"]
    elif is_macos():
        commands["network_interface"] = ["ifconfig", "networksetup"]
        commands["wireless"] = ["networksetup"]
        commands["scanning"] = ["airport", "wdutil"]
    elif is_windows():
        commands["network_interface"] = ["netsh"]
        commands["wireless"] = ["netsh"]
        commands["scanning"] = ["netsh"]

    return commands


def _is_windows_admin() -> bool:
    """Check if running as admin on Windows.

    Returns:
        True if admin, False otherwise
    """
    if not is_windows():
        return False
    try:
        import ctypes

        # Use getattr to avoid mypy errors on non-Windows platforms
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        return bool(windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def require_root() -> bool:
    """Check if root/admin privileges are required for current platform.

    Returns:
        True if root privileges are typically required, False otherwise
    """
    if is_windows():
        return not _is_windows_admin()
    else:
        # Unix-like systems require root (euid == 0)
        try:
            return os.geteuid() != 0
        except AttributeError:
            return False


def get_root_status() -> Tuple[bool, str]:
    """Get current root/admin status.

    Returns:
        Tuple of (is_root, status_message)
    """
    if is_windows():
        is_admin = _is_windows_admin()
        if is_admin:
            return True, "Running with administrator privileges"
        else:
            return False, "Administrator privileges required"
    else:
        try:
            euid = os.geteuid()
            uid = os.getuid()
            if euid == 0:
                return True, f"Running as root (EUID: {euid}, UID: {uid})"
            else:
                return (
                    False,
                    f"Root privileges required (current EUID: {euid}, UID: {uid})",
                )
        except AttributeError:
            return (
                False,
                "Could not determine root status (platform may not support it)",
            )


def get_python_executable() -> str:
    """Get the current Python executable path.

    Returns:
        Path to Python executable
    """
    return sys.executable


def get_venv_python_path(project_root: Optional[str] = None) -> Optional[str]:
    """Get the path to venv Python executable.

    Args:
        project_root: Optional project root directory. If None, tries to detect it.

    Returns:
        Path to venv Python if exists, None otherwise
    """
    if project_root is None:
        # Try to detect project root from current file location
        current_file = os.path.abspath(__file__)
        # Go up from utils/platform_utils.py to project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

    venv_python = os.path.join(project_root, "venv", "bin", "python3")
    if os.path.exists(venv_python):
        return venv_python

    # Also check for Windows venv structure
    venv_python_win = os.path.join(project_root, "venv", "Scripts", "python.exe")
    if os.path.exists(venv_python_win):
        return venv_python_win

    return None


def get_system_python_paths() -> List[str]:
    """Get common system Python paths for current platform.

    Returns:
        List of potential Python executable paths
    """
    paths: List[str] = []

    if is_macos():
        paths = [
            "/usr/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
        ]
    elif is_linux():
        paths = [
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/bin/python3",
        ]
    elif is_windows():
        # Windows Python paths are more variable
        # Common locations
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.environ.get(
            "ProgramFiles(x86)", "C:\\Program Files (x86)"
        )
        paths = [
            os.path.join(program_files, "Python3*", "python.exe"),
            os.path.join(program_files_x86, "Python3*", "python.exe"),
            os.path.join(
                os.environ.get("LOCALAPPDATA", ""),
                "Programs",
                "Python",
                "Python3*",
                "python.exe",
            ),
        ]
        # Filter out non-existent paths
        paths = [p for p in paths if os.path.exists(p)]

    return paths


def get_airport_path() -> Optional[str]:
    """Get the path to macOS airport utility.

    Returns:
        Path to airport utility if exists, None otherwise
    """
    if not is_macos():
        return None

    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if os.path.exists(airport_path):
        return airport_path
    return None


def get_bpf_devices() -> List[str]:
    """Get available BPF devices on macOS.

    Returns:
        List of BPF device paths
    """
    if not is_macos():
        return []

    import glob

    bpf_devices = glob.glob("/dev/bpf*")
    return sorted(bpf_devices)


def format_platform_info() -> str:
    """Get formatted platform information string.

    Returns:
        Formatted string with platform details
    """
    platform_type = get_platform_type()
    info = f"Platform: {platform_type.value}\n"
    info += f"System: {platform.system()}\n"
    info += f"Release: {platform.release()}\n"
    info += f"Version: {platform.version()}\n"
    info += f"Machine: {platform.machine()}\n"
    info += f"Python: {sys.version.split()[0]}\n"

    root_status, msg = get_root_status()
    info += f"Root/Admin: {'Yes' if root_status else 'No'} ({msg})\n"

    return info


def get_own_mac(interface: str) -> Optional[str]:
    """Best-effort local MAC address lookup across iproute2/ifconfig."""
    for cmd in (["ip", "link", "show", interface], ["ifconfig", interface]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            match = re.search(
                r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout
            )
            if match:
                return match.group(1)
    return None
