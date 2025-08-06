"""
Utility modules for WiFi jamming tool.
"""

from .logger import RichLogger, SimpleLogger

__all__ = ['RichLogger', 'SimpleLogger']

# Platform-specific imports
import platform
if platform.system() == "Darwin":
    from .macos_interfaces import get_macos_wireless_interfaces, check_interface_status, get_interface_info
    __all__.extend(['get_macos_wireless_interfaces', 'check_interface_status', 'get_interface_info']) 