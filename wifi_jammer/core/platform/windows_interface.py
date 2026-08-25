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




class WindowsInterface(IPlatformInterface):
    """Windows-specific interface detection."""

    def get_platform_type(self) -> PlatformType:
        return PlatformType.WINDOWS

    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use netsh to get interfaces
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    if "Wi-Fi" in line or "Wireless" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            iface_name = parts[3]
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
        return self.get_all_interfaces()

    def check_interface_status(self, interface_name: str) -> str:
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and interface_name in result.stdout:
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
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            status = "Available" if interface_name in result.stdout else "Not Available"
            is_wireless = "Wi-Fi" in result.stdout or "Wireless" in result.stdout

            return InterfaceInfo(
                name=interface_name,
                status=status,
                type="Wireless" if is_wireless else "Ethernet",
                mac_address="Unknown",  # Would need additional command to get MAC
                capabilities=[],
                is_wireless=is_wireless,
                is_monitor_capable=False,  # Windows has limited monitor mode support
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
        # Windows has very limited monitor mode support
        return False

    def set_channel(self, interface_name: str, channel: int) -> bool:
        # Windows has limited channel setting support
        return False

