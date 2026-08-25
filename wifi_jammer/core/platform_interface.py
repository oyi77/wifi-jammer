"""Backward-compatible shim for the pre-split module layout.

Implementation lives in :mod:`wifi_jammer.core.platform.*`; every historical
name is re-exported here so existing imports keep working.
"""

from wifi_jammer.core.platform.base_types import (  # noqa: F401
    InterfaceInfo,
    IPlatformInterface,
    PlatformType,
)
from wifi_jammer.core.platform.linux_interface import LinuxInterface  # noqa: F401
from wifi_jammer.core.platform.macos_interface import MacOSInterface  # noqa: F401
from wifi_jammer.core.platform.windows_interface import WindowsInterface  # noqa: F401
from wifi_jammer.core.platform.factory import PlatformInterfaceFactory  # noqa: F401

__all__ = [
    "PlatformType",
    "InterfaceInfo",
    "IPlatformInterface",
    "LinuxInterface",
    "MacOSInterface",
    "WindowsInterface",
    "PlatformInterfaceFactory",
]
