"""
macOS-specific utilities for wireless interface detection.
"""

import subprocess
import re
from typing import List


def get_macos_wireless_interfaces() -> List[str]:
    """Get wireless interfaces on macOS using various methods."""
    interfaces = []
    
    # Method 1: Use system_profiler
    try:
        result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Look for interface names in the output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Interface:' in line:
                    iface = line.split(':')[1].strip()
                    if iface and iface not in interfaces:
                        interfaces.append(iface)
    except Exception:
        pass
    
    # Method 2: Use networksetup
    try:
        result = subprocess.run(['networksetup', '-listallhardwareports'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Wi-Fi' in line or 'AirPort' in line:
                    # Look for the device name in the next few lines
                    for j in range(i+1, min(i+5, len(lines))):
                        if 'Device:' in lines[j]:
                            device = lines[j].split(':')[1].strip()
                            if device and device not in interfaces:
                                interfaces.append(device)
                            break
    except Exception:
        pass
    
    # Method 3: Use ifconfig to find wireless interfaces
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Look for wireless interfaces (en0, en1, etc.)
            lines = result.stdout.split('\n')
            for line in lines:
                # Match interface names like en0, en1, etc.
                match = re.match(r'^(\w+):', line)
                if match:
                    iface = match.group(1)
                    if iface.startswith('en') and iface not in interfaces:
                        # Check if it's actually wireless by looking for wireless capabilities
                        try:
                            ifconfig_result = subprocess.run(['ifconfig', iface], 
                                                          capture_output=True, text=True, timeout=5)
                            if ifconfig_result.returncode == 0:
                                # If we can get interface info, it's likely available
                                interfaces.append(iface)
                        except Exception:
                            pass
    except Exception:
        pass
    
    # Method 4: Common macOS wireless interface names
    common_wireless = ['en0', 'en1']
    for iface in common_wireless:
        if iface not in interfaces:
            try:
                result = subprocess.run(['ifconfig', iface], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    interfaces.append(iface)
            except Exception:
                pass
    
    return interfaces


def check_interface_status(interface: str) -> str:
    """Check if a network interface is available on macOS."""
    try:
        result = subprocess.run(['ifconfig', interface], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return "Available"
        else:
            return "Not Available"
    except Exception:
        return "Unknown"


def get_interface_info(interface: str) -> dict:
    """Get detailed information about a network interface on macOS."""
    info = {
        'name': interface,
        'status': 'Unknown',
        'type': 'Unknown',
        'mac_address': 'Unknown'
    }
    
    try:
        result = subprocess.run(['ifconfig', interface], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            info['status'] = 'Available'
            
            # Parse ifconfig output
            output = result.stdout
            if 'UP' in output:
                info['status'] = 'Active'
            
            # Extract MAC address
            mac_match = re.search(r'ether\s+([0-9a-fA-F:]+)', output)
            if mac_match:
                info['mac_address'] = mac_match.group(1)
            
            # Determine type
            if 'wireless' in output.lower() or 'wifi' in output.lower():
                info['type'] = 'Wireless'
            else:
                info['type'] = 'Ethernet'
                
    except Exception:
        pass
    
    return info 