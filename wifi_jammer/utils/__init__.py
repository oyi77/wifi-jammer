"""
Utility modules for WiFi jamming tool.
"""

from .logger import RichLogger
from .warning_suppressor import setup_warning_suppression
from .modern_crypto import ModernCrypto, get_modern_crypto

# Import python_detector for macOS permission detection
try:
    from .python_detector import find_python_with_permission, get_best_python
    from .platform_utils import (
        get_platform_type, is_linux, is_macos, is_windows, is_unix_like,
        check_command_available, check_commands_available,
        require_root, get_root_status, PlatformType
    )
    __all__ = [
        'RichLogger', 
        'setup_warning_suppression',
        'ModernCrypto',
        'get_modern_crypto',
        'find_python_with_permission',
        'get_best_python',
        'get_platform_type', 'is_linux', 'is_macos', 'is_windows', 'is_unix_like',
        'check_command_available', 'check_commands_available',
        'require_root', 'get_root_status', 'PlatformType'
    ]
except ImportError:
    from .platform_utils import (
        get_platform_type, is_linux, is_macos, is_windows, is_unix_like,
        check_command_available, check_commands_available,
        require_root, get_root_status, PlatformType
    )
    __all__ = [
        'RichLogger', 
        'setup_warning_suppression',
        'ModernCrypto',
        'get_modern_crypto',
        'get_platform_type', 'is_linux', 'is_macos', 'is_windows', 'is_unix_like',
        'check_command_available', 'check_commands_available',
        'require_root', 'get_root_status', 'PlatformType'
    ] 