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




class LinuxInterface(IPlatformInterface):
    """Linux-specific interface detection."""

    def get_platform_type(self) -> PlatformType:
        return PlatformType.LINUX

    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use ip link to get interfaces
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    match = re.match(r"^\d+:\s+(\w+):", line)
                    if match:
                        iface_name = match.group(1)
                        info = self.get_interface_info(iface_name)
                        if info:
                            interfaces.append(info)
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            ValueError,
        ):
            pass
        return interfaces

    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        wireless_interfaces = []
        try:
            # Use iwconfig to find wireless interfaces
            result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    match = re.match(r"^(\w+)\s+", line)
                    if match:
                        iface_name = match.group(1)
                        info = self.get_interface_info(iface_name)
                        if info and info.is_wireless:
                            wireless_interfaces.append(info)
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            ValueError,
        ):
            pass
        return wireless_interfaces

    def check_interface_status(self, interface_name: str) -> str:
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "UP" in result.stdout:
                return "Available"
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
        try:
            # Get interface status
            result = subprocess.run(
                ["ip", "link", "show", interface_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            status = "Available" if "UP" in result.stdout else "Not Available"

            # Get MAC address
            mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]+)", result.stdout)
            mac_address = mac_match.group(1) if mac_match else "Unknown"

            # Check if wireless: trust sysfs first (covers systemd predictable
            # names like wlp3s0), fall back to common name prefixes when the
            # sysfs entries are unavailable (containers, unusual kernels)
            is_wireless = (
                os.path.isdir(f"/sys/class/net/{interface_name}/wireless")
                or os.path.isdir(f"/sys/class/net/{interface_name}/phy80211")
                or interface_name.startswith(("wlan", "wifi", "ath", "wlp"))
            )

            # Check monitor mode capability
            is_monitor_capable = is_wireless

            return InterfaceInfo(
                name=interface_name,
                status=status,
                type="Wireless" if is_wireless else "Ethernet",
                mac_address=mac_address,
                capabilities=["monitor"] if is_monitor_capable else [],
                is_wireless=is_wireless,
                is_monitor_capable=is_monitor_capable,
            )
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            ValueError,
            AttributeError,
        ):
            return None

    def set_monitor_mode(self, interface_name: str) -> bool:
        try:
            result = subprocess.run(
                ["sudo", "iwconfig", interface_name, "mode", "monitor"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            PermissionError,
        ):
            return False

    def set_channel(self, interface_name: str, channel: int) -> bool:
        try:
            result = subprocess.run(
                ["sudo", "iwconfig", interface_name, "channel", str(channel)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            PermissionError,
        ):
            return False

