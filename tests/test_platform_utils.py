#!/usr/bin/env python3
"""
Tests for platform utilities.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import platform
import glob

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.utils.platform_utils import (
    PlatformType, get_platform_type, is_linux, is_macos, is_windows,
    is_unix_like, check_command_available, check_commands_available,
    get_platform_specific_commands, require_root, get_root_status,
    get_python_executable, get_venv_python_path, get_system_python_paths,
    get_airport_path, get_bpf_devices, format_platform_info
)


class TestPlatformDetection(unittest.TestCase):
    """Test platform detection functions."""
    
    def test_get_platform_type_linux(self):
        """Test platform type detection for Linux."""
        with patch('platform.system', return_value='Linux'):
            # Reset cached value
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            platform_type = get_platform_type()
            self.assertEqual(platform_type, PlatformType.LINUX)
    
    def test_get_platform_type_macos(self):
        """Test platform type detection for macOS."""
        with patch('platform.system', return_value='Darwin'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            platform_type = get_platform_type()
            self.assertEqual(platform_type, PlatformType.MACOS)
    
    def test_get_platform_type_windows(self):
        """Test platform type detection for Windows."""
        with patch('platform.system', return_value='Windows'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            platform_type = get_platform_type()
            self.assertEqual(platform_type, PlatformType.WINDOWS)
    
    def test_get_platform_type_unknown(self):
        """Test platform type detection for unknown platform."""
        with patch('platform.system', return_value='UnknownOS'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            platform_type = get_platform_type()
            self.assertEqual(platform_type, PlatformType.UNKNOWN)
    
    def test_is_linux(self):
        """Test is_linux function."""
        with patch('platform.system', return_value='Linux'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertTrue(is_linux())
            self.assertFalse(is_macos())
            self.assertFalse(is_windows())
    
    def test_is_macos(self):
        """Test is_macos function."""
        with patch('platform.system', return_value='Darwin'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertTrue(is_macos())
            self.assertFalse(is_linux())
            self.assertFalse(is_windows())
    
    def test_is_windows(self):
        """Test is_windows function."""
        with patch('platform.system', return_value='Windows'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertTrue(is_windows())
            self.assertFalse(is_linux())
            self.assertFalse(is_macos())
    
    def test_is_unix_like(self):
        """Test is_unix_like function."""
        with patch('platform.system', return_value='Linux'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertTrue(is_unix_like())
        
        with patch('platform.system', return_value='Darwin'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertTrue(is_unix_like())
        
        with patch('platform.system', return_value='Windows'):
            import wifi_jammer.utils.platform_utils as pu
            pu._platform_type = None
            self.assertFalse(is_unix_like())


class TestCommandAvailability(unittest.TestCase):
    """Test command availability checking."""
    
    @patch('shutil.which')
    def test_check_command_available(self, mock_which):
        """Test checking if command is available."""
        mock_which.return_value = '/usr/bin/python3'
        self.assertTrue(check_command_available('python3'))
        mock_which.assert_called_once_with('python3')
    
    @patch('shutil.which')
    def test_check_command_unavailable(self, mock_which):
        """Test checking if command is unavailable."""
        mock_which.return_value = None
        self.assertFalse(check_command_available('nonexistent'))
    
    @patch('shutil.which')
    def test_check_commands_available(self, mock_which):
        """Test checking multiple commands."""
        def which_side_effect(cmd):
            return '/usr/bin/' + cmd if cmd in ['python3', 'pip3'] else None
        
        mock_which.side_effect = which_side_effect
        available, missing = check_commands_available(['python3', 'pip3', 'nonexistent'])
        
        self.assertIn('python3', available)
        self.assertIn('pip3', available)
        self.assertIn('nonexistent', missing)


class TestPlatformSpecificCommands(unittest.TestCase):
    """Test platform-specific command detection."""
    
    def test_get_platform_specific_commands_linux(self):
        """Test getting platform-specific commands for Linux."""
        with patch('wifi_jammer.utils.platform_utils.is_linux', return_value=True):
            commands = get_platform_specific_commands()
            self.assertIn('network_interface', commands)
            self.assertIn('wireless', commands)
            self.assertIn('scanning', commands)
    
    def test_get_platform_specific_commands_macos(self):
        """Test getting platform-specific commands for macOS."""
        with patch('wifi_jammer.utils.platform_utils.is_macos', return_value=True):
            commands = get_platform_specific_commands()
            self.assertIn('network_interface', commands)
            self.assertIn('wireless', commands)
            self.assertIn('scanning', commands)
    
    def test_get_platform_specific_commands_windows(self):
        """Test getting platform-specific commands for Windows."""
        with patch('wifi_jammer.utils.platform_utils.is_windows', return_value=True):
            commands = get_platform_specific_commands()
            self.assertIn('network_interface', commands)
            self.assertIn('wireless', commands)
            self.assertIn('scanning', commands)


class TestRootStatus(unittest.TestCase):
    """Test root/admin status checking."""
    
    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=False)
    @patch('os.geteuid')
    def test_require_root_unix_root(self, mock_geteuid, mock_is_windows):
        """Test require_root on Unix with root privileges."""
        mock_geteuid.return_value = 0
        self.assertFalse(require_root())  # False means has root
    
    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=False)
    @patch('os.geteuid')
    def test_require_root_unix_not_root(self, mock_geteuid, mock_is_windows):
        """Test require_root on Unix without root privileges."""
        mock_geteuid.return_value = 1000
        self.assertTrue(require_root())  # True means needs root
    
    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=True)
    @patch('ctypes.windll', create=True)
    def test_require_root_windows_admin(self, mock_windll, mock_is_windows):
        """Test require_root on Windows with admin privileges."""
        mock_windll.shell32.IsUserAnAdmin.return_value = True
        self.assertFalse(require_root())

    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=True)
    @patch('ctypes.windll', create=True)
    def test_require_root_windows_not_admin(self, mock_windll, mock_is_windows):
        """Test require_root on Windows without admin privileges."""
        mock_windll.shell32.IsUserAnAdmin.return_value = False
        self.assertTrue(require_root())
    
    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=False)
    @patch('os.geteuid')
    @patch('os.getuid')
    def test_get_root_status_unix_root(self, mock_getuid, mock_geteuid, mock_is_windows):
        """Test get_root_status on Unix with root."""
        mock_geteuid.return_value = 0
        mock_getuid.return_value = 0
        is_root, msg = get_root_status()
        self.assertTrue(is_root)
        self.assertIn('root', msg.lower())
    
    @patch('wifi_jammer.utils.platform_utils.is_windows', return_value=False)
    @patch('os.geteuid')
    @patch('os.getuid')
    def test_get_root_status_unix_not_root(self, mock_getuid, mock_geteuid, mock_is_windows):
        """Test get_root_status on Unix without root."""
        mock_geteuid.return_value = 1000
        mock_getuid.return_value = 1000
        is_root, msg = get_root_status()
        self.assertFalse(is_root)
        self.assertIn('required', msg.lower())


class TestPythonPaths(unittest.TestCase):
    """Test Python path utilities."""
    
    def test_get_python_executable(self):
        """Test getting Python executable path."""
        path = get_python_executable()
        self.assertIsInstance(path, str)
        self.assertIn('python', path.lower())
    
    @patch('os.path.exists')
    def test_get_venv_python_path_exists(self, mock_exists):
        """Test getting venv Python path when it exists."""
        mock_exists.return_value = True
        path = get_venv_python_path('/test/project')
        self.assertIsNotNone(path)
        self.assertIn('venv', path)
    
    @patch('os.path.exists')
    def test_get_venv_python_path_not_exists(self, mock_exists):
        """Test getting venv Python path when it doesn't exist."""
        mock_exists.return_value = False
        path = get_venv_python_path('/test/project')
        self.assertIsNone(path)
    
    def test_get_system_python_paths_linux(self):
        """Test getting system Python paths on Linux."""
        with patch('wifi_jammer.utils.platform_utils.is_linux', return_value=True):
            paths = get_system_python_paths()
            self.assertIsInstance(paths, list)
            self.assertGreater(len(paths), 0)
    
    def test_get_system_python_paths_macos(self):
        """Test getting system Python paths on macOS."""
        with patch('wifi_jammer.utils.platform_utils.is_macos', return_value=True):
            paths = get_system_python_paths()
            self.assertIsInstance(paths, list)
            self.assertGreater(len(paths), 0)


class TestMacOSUtilities(unittest.TestCase):
    """Test macOS-specific utilities."""
    
    @patch('wifi_jammer.utils.platform_utils.is_macos', return_value=False)
    def test_get_airport_path_not_macos(self, mock_is_macos):
        """Test get_airport_path on non-macOS."""
        path = get_airport_path()
        self.assertIsNone(path)
    
    @patch('wifi_jammer.utils.platform_utils.is_macos', return_value=True)
    @patch('os.path.exists')
    def test_get_airport_path_exists(self, mock_exists, mock_is_macos):
        """Test get_airport_path when airport exists."""
        mock_exists.return_value = True
        path = get_airport_path()
        self.assertIsNotNone(path)
        self.assertIn('airport', path)
    
    @patch('wifi_jammer.utils.platform_utils.is_macos', return_value=False)
    def test_get_bpf_devices_not_macos(self, mock_is_macos):
        """Test get_bpf_devices on non-macOS."""
        devices = get_bpf_devices()
        self.assertEqual(devices, [])
    
    @patch('wifi_jammer.utils.platform_utils.is_macos', return_value=True)
    @patch('glob.glob')
    def test_get_bpf_devices_macos(self, mock_glob, mock_is_macos):
        """Test get_bpf_devices on macOS."""
        mock_glob.return_value = ['/dev/bpf0', '/dev/bpf1']
        devices = get_bpf_devices()
        self.assertEqual(len(devices), 2)
        self.assertIn('/dev/bpf0', devices)


class TestPlatformInfo(unittest.TestCase):
    """Test platform information formatting."""
    
    @patch('platform.system')
    @patch('platform.release')
    @patch('platform.machine')
    @patch('wifi_jammer.utils.platform_utils.get_platform_type')
    @patch('wifi_jammer.utils.platform_utils.get_root_status')
    @patch('wifi_jammer.utils.platform_utils.get_platform_specific_commands')
    @patch('wifi_jammer.utils.platform_utils.check_commands_available')
    def test_format_platform_info(self, mock_check, mock_get_commands, mock_root,
                                   mock_platform_type, mock_machine, mock_release, mock_system):
        """Test formatting platform information."""
        mock_system.return_value = 'Linux'
        mock_release.return_value = '5.10'
        mock_machine.return_value = 'x86_64'
        mock_platform_type.return_value = PlatformType.LINUX
        mock_root.return_value = (False, "Root required")
        mock_get_commands.return_value = {
            'network_interface': ['ip', 'iwconfig'],
            'wireless': ['iwconfig'],
            'scanning': ['iwlist']
        }
        mock_check.return_value = (['ip'], ['iwconfig'])
        
        info = format_platform_info()
        self.assertIn('Platform', info)
        self.assertIn('System', info)
        self.assertIn('Linux', info)


if __name__ == '__main__':
    unittest.main()

