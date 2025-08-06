"""
Platform abstraction layer for interface detection.
Following SOLID principles with clear separation of concerns.
"""

import platform
import subprocess
import re
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
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


class LinuxInterface(IPlatformInterface):
    """Linux-specific interface detection."""
    
    def get_platform_type(self) -> PlatformType:
        return PlatformType.LINUX
    
    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use ip link to get interfaces
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    match = re.match(r'^\d+:\s+(\w+):', line)
                    if match:
                        iface_name = match.group(1)
                        info = self.get_interface_info(iface_name)
                        if info:
                            interfaces.append(info)
        except Exception:
            pass
        return interfaces
    
    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        wireless_interfaces = []
        try:
            # Use iwconfig to find wireless interfaces
            result = subprocess.run(['iwconfig'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    match = re.match(r'^(\w+)\s+', line)
                    if match:
                        iface_name = match.group(1)
                        info = self.get_interface_info(iface_name)
                        if info and info.is_wireless:
                            wireless_interfaces.append(info)
        except Exception:
            pass
        return wireless_interfaces
    
    def check_interface_status(self, interface_name: str) -> str:
        try:
            result = subprocess.run(['ip', 'link', 'show', interface_name], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'UP' in result.stdout:
                return "Available"
            else:
                return "Not Available"
        except Exception:
            return "Unknown"
    
    def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        try:
            # Get interface status
            result = subprocess.run(['ip', 'link', 'show', interface_name], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
            
            status = "Available" if "UP" in result.stdout else "Not Available"
            
            # Get MAC address
            mac_match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', result.stdout)
            mac_address = mac_match.group(1) if mac_match else "Unknown"
            
            # Check if wireless
            is_wireless = interface_name.startswith(('wlan', 'wifi', 'ath'))
            
            # Check monitor mode capability
            is_monitor_capable = is_wireless
            
            return InterfaceInfo(
                name=interface_name,
                status=status,
                type="Wireless" if is_wireless else "Ethernet",
                mac_address=mac_address,
                capabilities=["monitor"] if is_monitor_capable else [],
                is_wireless=is_wireless,
                is_monitor_capable=is_monitor_capable
            )
        except Exception:
            return None
    
    def set_monitor_mode(self, interface_name: str) -> bool:
        try:
            result = subprocess.run(['sudo', 'iwconfig', interface_name, 'mode', 'monitor'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def set_channel(self, interface_name: str, channel: int) -> bool:
        try:
            result = subprocess.run(['sudo', 'iwconfig', interface_name, 'channel', str(channel)], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False


class MacOSInterface(IPlatformInterface):
    """macOS-specific interface detection."""
    
    def get_platform_type(self) -> PlatformType:
        return PlatformType.MACOS
    
    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use ifconfig to get all interfaces
            result = subprocess.run(['ifconfig'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_interface = None
                
                for line in lines:
                    # Match interface name
                    match = re.match(r'^(\w+):', line)
                    if match:
                        if current_interface:
                            interfaces.append(current_interface)
                        current_interface = self.get_interface_info(match.group(1))
                
                # Add the last interface
                if current_interface:
                    interfaces.append(current_interface)
        except Exception:
            pass
        return interfaces
    
    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        wireless_interfaces = []
        try:
            # Use system_profiler to get wireless interfaces
            result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_interface = None
                
                for i, line in enumerate(lines):
                    # Look for interface names (lines ending with ':')
                    if line.strip().endswith(':') and not line.strip().startswith('Wi-Fi:'):
                        iface_name = line.strip()[:-1]  # Remove the colon
                        # Check if this interface has wireless capabilities
                        for j in range(i+1, min(i+20, len(lines))):
                            if 'Card Type: Wi-Fi' in lines[j]:
                                info = self.get_interface_info(iface_name)
                                if info and info.is_wireless:
                                    wireless_interfaces.append(info)
                                break
                            elif j < len(lines) and lines[j].strip().endswith(':') and not lines[j].strip().startswith('Wi-Fi:'):
                                # Found another interface, stop searching
                                break
        except Exception:
            pass
        
        # Fallback: check common wireless interface names
        if not wireless_interfaces:
            common_wireless = ['en0', 'en1']
            for iface_name in common_wireless:
                info = self.get_interface_info(iface_name)
                if info and info.is_wireless:
                    wireless_interfaces.append(info)
        
        return wireless_interfaces
    
    def check_interface_status(self, interface_name: str) -> str:
        try:
            result = subprocess.run(['ifconfig', interface_name], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                if 'UP' in result.stdout:
                    return "Available"
                else:
                    return "Not Available"
            else:
                return "Not Available"
        except Exception:
            return "Unknown"
    
    def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        try:
            result = subprocess.run(['ifconfig', interface_name], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
            
            output = result.stdout
            status = "Available" if "UP" in output else "Not Available"
            
            # Extract MAC address
            mac_match = re.search(r'ether\s+([0-9a-fA-F:]+)', output)
            mac_address = mac_match.group(1) if mac_match else "Unknown"
            
            # Determine if wireless by checking system_profiler
            is_wireless = False
            try:
                profiler_result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                               capture_output=True, text=True, timeout=10)
                if profiler_result.returncode == 0:
                    # Check if this interface appears in the wireless section
                    if interface_name in profiler_result.stdout:
                        # Look for "Card Type: Wi-Fi" near this interface
                        lines = profiler_result.stdout.split('\n')
                        for i, line in enumerate(lines):
                            if interface_name in line and line.strip().endswith(':'):
                                # Check next few lines for "Card Type: Wi-Fi"
                                for j in range(i+1, min(i+10, len(lines))):
                                    if 'Card Type: Wi-Fi' in lines[j]:
                                        is_wireless = True
                                        break
                                    elif j < len(lines) and lines[j].strip().endswith(':') and not lines[j].strip().startswith('Wi-Fi:'):
                                        # Found another interface, stop searching
                                        break
            except Exception:
                # Fallback: assume en0, en1, awdl0 are wireless
                is_wireless = interface_name.startswith('en') or interface_name.startswith('awdl')
            
            # Monitor mode capability (limited on macOS)
            is_monitor_capable = is_wireless
            
            return InterfaceInfo(
                name=interface_name,
                status=status,
                type="Wireless" if is_wireless else "Ethernet",
                mac_address=mac_address,
                capabilities=["monitor"] if is_monitor_capable else [],
                is_wireless=is_wireless,
                is_monitor_capable=is_monitor_capable
            )
        except Exception:
            return None
    
    def set_monitor_mode(self, interface_name: str) -> bool:
        # macOS has limited monitor mode support
        # This would require additional tools like airmon-ng or manual configuration
        return False
    
    def set_channel(self, interface_name: str, channel: int) -> bool:
        # macOS has limited channel setting support
        return False


class WindowsInterface(IPlatformInterface):
    """Windows-specific interface detection."""
    
    def get_platform_type(self) -> PlatformType:
        return PlatformType.WINDOWS
    
    def get_all_interfaces(self) -> List[InterfaceInfo]:
        interfaces = []
        try:
            # Use netsh to get interfaces
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Wi-Fi' in line or 'Wireless' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            iface_name = parts[3]
                            info = self.get_interface_info(iface_name)
                            if info:
                                interfaces.append(info)
        except Exception:
            pass
        return interfaces
    
    def get_wireless_interfaces(self) -> List[InterfaceInfo]:
        return self.get_all_interfaces()
    
    def check_interface_status(self, interface_name: str) -> str:
        try:
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and interface_name in result.stdout:
                return "Available"
            else:
                return "Not Available"
        except Exception:
            return "Unknown"
    
    def get_interface_info(self, interface_name: str) -> Optional[InterfaceInfo]:
        try:
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=5)
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
                is_monitor_capable=False  # Windows has limited monitor mode support
            )
        except Exception:
            return None
    
    def set_monitor_mode(self, interface_name: str) -> bool:
        # Windows has very limited monitor mode support
        return False
    
    def set_channel(self, interface_name: str, channel: int) -> bool:
        # Windows has limited channel setting support
        return False


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