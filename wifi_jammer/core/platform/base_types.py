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




class PlatformType(Enum):
    """Supported platform types."""

    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass


class InterfaceInfo:
    """Interface information data class."""

    name: str
    status: str
    type: str
    mac_address: str
    capabilities: List[str]
    is_wireless: bool
    is_monitor_capable: bool


class IPlatformInterface(ABC):
    """Abstract interface for platform-specific interface detection."""

    @abstractmethod
    def get_platform_type(self) -> PlatformType:
        """Get the current platform type."""
        pass

    @abstractmethod
    def get_all_interfaces(self) -> List[InterfaceInfo]:
        """Get all available network interfaces."""
        pass

    @abstractmethod
    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        """Get wireless interfaces only."""
        pass

    @abstractmethod
    def check_interface_status(self, interface_name: str) -> str:
        """Check if an interface is available."""
        pass

    @abstractmethod
    def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        """Get detailed information about a specific interface."""
        pass

    @abstractmethod
    def set_monitor_mode(self, interface_name: str) -> bool:
        """Set interface to monitor mode."""
        pass

    @abstractmethod
    def set_channel(self, interface_name: str, channel: int) -> bool:
        """Set interface channel."""
        pass

