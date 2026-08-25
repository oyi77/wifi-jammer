"""
Platform abstraction layer for interface detection.
Following SOLID principles with clear separation of concerns.
"""

import platform
import subprocess
import re
import time
import os
from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum
from wifi_jammer.core.platform.base_types import (  # noqa: F401
    InterfaceInfo,
    IPlatformInterface,
    PlatformType,
)




class MacOSInterface(IPlatformInterface):
    """macOS-specific interface detection."""

    AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    def __init__(self) -> None:
        self._ns_cache: Optional[str] = None
        self._ns_cache_time = 0.0

    def _get_ns_output(self) -> str:
        """Get networksetup output with simple caching."""
        current_time = time.time()
        if self._ns_cache is None or current_time - self._ns_cache_time > 30:
            try:
                result = subprocess.run(
                    ["networksetup", "-listallhardwareports"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    self._ns_cache = result.stdout
                    self._ns_cache_time = current_time
                else:
                    return ""
            except (
                subprocess.TimeoutExpired,
                subprocess.CalledProcessError,
                FileNotFoundError,
                OSError,
            ):
                return ""
        return self._ns_cache or ""

    def get_platform_type(self) -> PlatformType:
        return PlatformType.MACOS

    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use ifconfig -l to get list of names
            result = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                iface_names = result.stdout.strip().split()
                for name in iface_names:
                    try:
                        info = self.get_interface_info(name)
                        if info:
                            interfaces.append(info)
                    except (
                        subprocess.TimeoutExpired,
                        subprocess.CalledProcessError,
                        FileNotFoundError,
                        OSError,
                        ValueError,
                        AttributeError,
                    ):
                        continue
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
        ):
            pass
        return interfaces

    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        """Get wireless interfaces on macOS with improved detection."""
        wireless_interfaces = []
        ns_output = self._get_ns_output()

        # Method 1: Use networksetup to find Wi-Fi interfaces
        if ns_output:
            lines = ns_output.split("\n")
            current_port = None
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                # Check for hardware port line
                if line_stripped.startswith("Hardware Port:"):
                    port_name = line_stripped.replace("Hardware Port:", "").strip()
                    # Check if it's Wi-Fi or AirPort
                    if "Wi-Fi" in port_name or "AirPort" in port_name:
                        current_port = port_name
                    else:
                        current_port = None
                # Check for device line
                elif current_port and line_stripped.startswith("Device:"):
                    match = re.search(r"Device:\s*(\w+)", line_stripped)
                    if match:
                        iface_name = match.group(1)
                        info = self.get_interface_info(iface_name)
                        if info and info.is_wireless:
                            wireless_interfaces.append(info)
                        current_port = None

        # Method 2: Fallback - check all interfaces and identify wireless ones
        if not wireless_interfaces:
            all_interfaces = self.get_all_interfaces()
            for iface in all_interfaces:
                if iface.is_wireless:
                    wireless_interfaces.append(iface)

        # Method 3: Last resort - check common macOS wireless interface names
        if not wireless_interfaces:
            common_wireless_names = ["en0", "en1", "wlan0", "wifi0"]
            for name in common_wireless_names:
                try:
                    info = self.get_interface_info(name)
                    if info and info.is_wireless:
                        # Only add if not already in list
                        if not any(i.name == info.name for i in wireless_interfaces):
                            wireless_interfaces.append(info)
                except (
                    subprocess.TimeoutExpired,
                    subprocess.CalledProcessError,
                    FileNotFoundError,
                    OSError,
                    ValueError,
                    AttributeError,
                ):
                    continue

        return wireless_interfaces

    def check_interface_status(self, interface_name: str) -> str:
        """Check interface status with improved macOS detection."""
        try:
            result = subprocess.run(
                ["/sbin/ifconfig", interface_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # Improved status detection for macOS
                if (
                    "status: active" in output
                    or "up" in output
                    or "running" in output
                    or "inet " in output
                ):
                    return "Available"
                else:
                    return "Not Available"
            else:
                return "Not Available"
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
        ):
            return "Unknown"

    def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        """Get interface information with improved macOS wireless detection."""
        try:
            result = subprocess.run(
                ["/sbin/ifconfig", interface_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            output_lower = output.lower()

            # Improved status detection for macOS
            status = "Not Available"
            if (
                "status: active" in output_lower
                or "up" in output_lower
                or "running" in output_lower
                or "inet " in output
            ):
                status = "Available"

            # Extract MAC address
            mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", output)
            mac_address = mac_match.group(1) if mac_match else "Unknown"

            # Improved wireless detection with multiple methods
            is_wireless = False

            # Method 1: Check networksetup output
            ns_output = self._get_ns_output()
            if ns_output:
                lines = ns_output.split("\n")
                for i, line in enumerate(lines):
                    if f"Device: {interface_name}" in line:
                        # Check previous lines for Wi-Fi/AirPort
                        for j in range(max(0, i - 3), i):
                            if "Wi-Fi" in lines[j] or "AirPort" in lines[j]:
                                is_wireless = True
                                break
                        if is_wireless:
                            break

            # Method 2: Check media type in ifconfig output
            if not is_wireless:
                is_wireless = (
                    "media: IEEE 802.11" in output
                    or "media: autoselect (802.11)" in output
                    or "media: autoselect mode 11n" in output
                    or "media: autoselect mode 11ac" in output
                )

            # Method 3: Check common macOS wireless interface names
            if not is_wireless:
                # en0 is typically Wi-Fi on macOS, but not always
                # Check if it has wireless characteristics
                if interface_name in ["en0", "en1"]:
                    # Additional check: if it has no IP or has specific wireless patterns
                    if "inet " not in output or "media: IEEE 802.11" in output:
                        is_wireless = True

            # Method 4: Check if interface supports wireless operations
            if not is_wireless and os.path.exists(self.AIRPORT_PATH):
                # Try to get info via airport (doesn't require sudo for basic info)
                try:
                    ap_result = subprocess.run(
                        [self.AIRPORT_PATH, interface_name, "-I"],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )
                    if ap_result.returncode == 0 and "SSID:" in ap_result.stdout:
                        is_wireless = True
                except (
                    subprocess.TimeoutExpired,
                    subprocess.CalledProcessError,
                    FileNotFoundError,
                    OSError,
                ):
                    pass

            # Monitor mode capability - macOS has limited support
            # Most modern Macs don't support monitor mode without special drivers
            is_monitor_capable = False
            if is_wireless:
                # Check if airport utility exists (required for monitor mode)
                if os.path.exists(self.AIRPORT_PATH):
                    # On macOS, monitor mode is very limited
                    # Only certain older Macs or with special drivers support it
                    # We'll mark it as capable but warn users it may not work
                    is_monitor_capable = True

            return InterfaceInfo(
                name=interface_name,
                status=status,
                type="Wireless" if is_wireless else "Ethernet",
                mac_address=mac_address,
                capabilities=["monitor"] if is_monitor_capable else [],
                is_wireless=is_wireless,
                is_monitor_capable=is_monitor_capable,
            )
        except Exception:
            # Log error but don't fail completely
            return None

    def set_monitor_mode(self, interface_name: str) -> bool:
        """Set interface to monitor mode on macOS.

        Note: Monitor mode is very limited on macOS and may not work on all systems.
        Most modern Macs don't support monitor mode without special drivers.
        """
        if not os.path.exists(self.AIRPORT_PATH):
            return False

        try:
            # Try to set monitor mode using airport utility
            # Note: This may require sudo and may not work on all Macs
            result = subprocess.run(
                ["sudo", self.AIRPORT_PATH, interface_name, "-z"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Check if it succeeded (return code 0)
            if result.returncode == 0:
                return True
            # Even if return code is non-zero, it might have worked
            # Check stderr for specific error messages
            if result.stderr:
                error_lower = result.stderr.lower()
                if (
                    "operation not permitted" in error_lower
                    or "permission denied" in error_lower
                ):
                    # Need sudo or permissions
                    return False
                elif "not supported" in error_lower or "unsupported" in error_lower:
                    # Monitor mode not supported on this Mac
                    return False
            # If no clear error, assume it might have worked
            return True
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            # Airport utility not found
            return False
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            OSError,
            PermissionError,
        ):
            return False

    def set_channel(self, interface_name: str, channel: int) -> bool:
        """Set interface channel on macOS.

        Note: Channel setting may not work in managed mode on macOS.
        Monitor mode is typically required for channel setting.
        """
        if not os.path.exists(self.AIRPORT_PATH):
            return False

        try:
            # Try to set channel using airport utility
            # Note: This may require sudo and monitor mode
            result = subprocess.run(
                ["sudo", self.AIRPORT_PATH, interface_name, f"--channel={channel}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Check if it succeeded
            if result.returncode == 0:
                return True
            # Check for specific errors
            if result.stderr:
                error_lower = result.stderr.lower()
                if "operation not permitted" in error_lower:
                    return False
                elif "not supported" in error_lower:
                    return False
            # If no clear error, might have worked
            return True
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            return False
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            OSError,
            PermissionError,
        ):
            return False

