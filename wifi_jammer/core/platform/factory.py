"""Runtime selection of the platform interface implementation."""

import platform

from wifi_jammer.core.platform.base_types import (
    InterfaceInfo,
    IPlatformInterface,
    PlatformType,
)
from wifi_jammer.core.platform.linux_interface import LinuxInterface
from wifi_jammer.core.platform.macos_interface import MacOSInterface
from wifi_jammer.core.platform.windows_interface import WindowsInterface


class PlatformInterfaceFactory:
    """Factory for creating platform-specific interface handlers."""

    @staticmethod
    def create() -> IPlatformInterface:
        """Create the appropriate platform interface handler."""
        system = platform.system().lower()

        if system == "linux":
            return LinuxInterface()
        elif system == "darwin":
            return MacOSInterface()
        elif system == "windows":
            return WindowsInterface()
        else:
            # Fallback to Linux interface for unknown systems
            return LinuxInterface()

