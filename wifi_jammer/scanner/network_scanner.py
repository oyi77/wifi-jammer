"""
Network scanner implementation using scapy.
"""

import time
import threading
import warnings
import platform as platform_system
import subprocess
import re
from typing import List, Optional, Callable
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from ..core.interfaces import INetworkScanner, NetworkInfo
from ..core.platform_interface import PlatformInterfaceFactory, IPlatformInterface
from ..utils.logger import RichLogger


# Suppress scapy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


class ScapyNetworkScanner(INetworkScanner):
    """Network scanner implementation using scapy."""
    
    def __init__(self, logger: Optional[RichLogger] = None):
        self.logger = logger or RichLogger()
        self._scanning = False
        self._networks = []
        self._lock = threading.Lock()
        self._platform_interface = PlatformInterfaceFactory.create()
    
    def get_interface_list(self) -> List[str]:
        """Get list of available wireless interfaces."""
        try:
            # Use platform-specific interface detection
            wireless_interfaces = self._platform_interface.get_wireless_interfaces()
            
            if not wireless_interfaces:
                self.logger.warning(f"No wireless interfaces detected on {self._platform_interface.get_platform_type().value}")
                return []
            
            # Return only interface names
            interface_names = [iface.name for iface in wireless_interfaces if iface.status == "Available"]
            
            if not interface_names:
                self.logger.warning("No available wireless interfaces found")
                return []
            
            return interface_names
            
        except Exception as e:
            self.logger.error(f"Error getting interface list: {e}")
            return []
    
    def scan_networks(self, interface: str, channel: Optional[int] = None) -> List[NetworkInfo]:
        """Scan for available networks."""
        self._networks = []
        self._scanning = True
        
        try:
            # Check if interface exists and is available
            interface_info = self._platform_interface.get_interface_info(interface)
            if not interface_info or interface_info.status != "Available":
                self.logger.error(f"Interface {interface} is not available")
                self._scanning = False
                return []
            
            # Use platform-specific scanning
            if platform_system.system() == "Darwin":
                # macOS-specific scanning
                self._scan_macos_networks(interface, channel)
            else:
                # Linux/Windows scanning
                self._scan_standard_networks(interface, channel)
            
        except Exception as e:
            self.logger.error(f"Error during network scan: {e}")
        finally:
            # Always ensure scanning state is reset
            self._scanning = False
        
        return self._networks.copy()
    
    def _scan_macos_networks(self, interface: str, channel: Optional[int] = None):
        """Scan networks using macOS-specific methods."""
        try:
            # Method 1: Use system_profiler to get current networks
            self.logger.info("Scanning using macOS system information...")
            result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self._parse_macos_networks(result.stdout)
            
            # Method 2: Try scapy scanning without monitor mode
            if not self._networks:
                self.logger.info("Trying scapy scanning...")
                self._scan_standard_networks(interface, channel)
                
        except Exception as e:
            self.logger.error(f"Error in macOS network scan: {e}")
    
    def _parse_macos_networks(self, output: str):
        """Parse macOS system_profiler output to extract network information."""
        try:
            lines = output.split('\n')
            networks_found = []
            
            # Look for "Other Local Wi-Fi Networks:" section
            in_networks_section = False
            current_network = None
            
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Check if we're entering the networks section
                if "Other Local Wi-Fi Networks:" in line:
                    in_networks_section = True
                    continue
                
                # If we're in the networks section, look for network names
                if in_networks_section:
                    # Skip empty lines and section headers
                    if not line or line.startswith('Wi-Fi:') or line.startswith('Interfaces:'):
                        continue
                    
                    # Check if this line looks like a network name (ends with ':')
                    if line.endswith(':') and not any(keyword in line for keyword in ['Card Type', 'Firmware', 'MAC Address', 'Supported', 'Wake On', 'AirDrop', 'Auto Unlock', 'Status', 'Current Network', 'Other Local', 'Software Versions']):
                        network_name = line[:-1].strip()  # Remove the colon
                        if network_name and len(network_name) > 0:
                            # Extract network info from the next few lines
                            network_info = self._extract_macos_network_info(lines, i)
                            if network_info:
                                with self._lock:
                                    self._networks.append(network_info)
                                    networks_found.append(network_name)
                
                # Stop parsing if we hit another major section
                elif in_networks_section and line.startswith('awdl0:'):
                    break
                    
        except Exception as e:
            self.logger.error(f"Error parsing macOS networks: {e}")
    
    def _extract_macos_network_info(self, lines: List[str], start_index: int) -> Optional[NetworkInfo]:
        """Extract network information from macOS system_profiler output."""
        try:
            network_name = lines[start_index].split(':')[0].strip()
            channel = 0
            encryption = "Unknown"
            rssi = -50
            
            # Look for network details in the next few lines
            for i in range(start_index + 1, min(start_index + 15, len(lines))):
                line = lines[i].strip()
                
                # Stop if we hit another network or section
                if line.endswith(':') and not any(keyword in line for keyword in ['PHY Mode', 'Channel', 'Security', 'Signal', 'Network Type']):
                    break
                
                if 'Channel:' in line:
                    # Extract channel number
                    channel_match = re.search(r'Channel:\s*(\d+)', line)
                    if channel_match:
                        channel = int(channel_match.group(1))
                
                elif 'Security:' in line:
                    # Extract encryption type
                    if 'WPA2' in line:
                        encryption = "WPA2"
                    elif 'WPA' in line:
                        encryption = "WPA"
                    elif 'WEP' in line:
                        encryption = "WEP"
                    else:
                        encryption = "Open"
                
                elif 'Signal' in line and 'dBm' in line:
                    # Extract signal strength
                    rssi_match = re.search(r'(-?\d+)\s*dBm', line)
                    if rssi_match:
                        rssi = int(rssi_match.group(1))
                
                elif line.startswith('Network Type:') or line.startswith('PHY Mode:'):
                    # Continue looking for more info
                    continue
            
            # Generate a dummy BSSID (since we don't have it from system_profiler)
            bssid = f"00:00:00:00:00:{hash(network_name) % 100:02x}"
            
            return NetworkInfo(
                ssid=network_name,
                bssid=bssid,
                channel=channel,
                rssi=rssi,
                encryption=encryption,
                clients=[]
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting network info: {e}")
            return None
    
    def _scan_standard_networks(self, interface: str, channel: Optional[int] = None):
        """Standard network scanning using scapy."""
        try:
            # Set interface to monitor mode if supported
            interface_info = self._platform_interface.get_interface_info(interface)
            if interface_info and interface_info.is_monitor_capable:
                if not self._platform_interface.set_monitor_mode(interface):
                    self.logger.warning(f"Could not set {interface} to monitor mode")
            
            # Start scanning in background
            scan_thread = threading.Thread(
                target=self._scan_thread,
                args=(interface, channel)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
            # Wait for scan to complete
            time.sleep(5)
            
        except Exception as e:
            self.logger.error(f"Error in standard network scan: {e}")
    
    def _scan_thread(self, interface: str, channel: Optional[int] = None):
        """Background thread for scanning networks."""
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                self._process_beacon_packet(pkt)
            elif pkt.haslayer(Dot11ProbeResp):
                self._process_probe_response(pkt)
        
        try:
            # Set channel if specified and supported
            if channel and self._platform_interface.get_interface_info(interface).is_monitor_capable:
                self._platform_interface.set_channel(interface, channel)
            
            # Start sniffing with error handling
            try:
                # Try with monitor mode first
                sniff(
                    iface=interface,
                    prn=packet_handler,
                    store=0,
                    timeout=5,
                    quiet=True
                )
            except Exception as e:
                self.logger.error(f"Error during packet sniffing: {e}")
                # Fallback: try without monitor mode
                if self._platform_interface.get_interface_info(interface).is_monitor_capable:
                    self.logger.info("Trying scan without monitor mode...")
                    try:
                        sniff(
                            iface=interface,
                            prn=packet_handler,
                            store=0,
                            timeout=5,
                            quiet=True
                        )
                    except Exception as e2:
                        self.logger.error(f"Scan failed even without monitor mode: {e2}")
                        # Final fallback: try with different parameters
                        try:
                            self.logger.info("Trying alternative scan method...")
                            sniff(
                                iface=interface,
                                prn=packet_handler,
                                store=0,
                                timeout=10,
                                quiet=True,
                                iface_hint=interface
                            )
                        except Exception as e3:
                            self.logger.error(f"All scan methods failed: {e3}")
            
        except Exception as e:
            self.logger.error(f"Error in scan thread: {e}")
    
    def _process_beacon_packet(self, pkt):
        """Process beacon packet to extract network info."""
        try:
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                ssid = None
                channel = None
                encryption = "Unknown"
                
                # Extract SSID
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode('utf-8', errors='ignore')
                            except:
                                ssid = None
                        elif elt.ID == 3:  # Channel
                            if len(elt.info) > 0:
                                channel = elt.info[0]
                
                # Determine encryption
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 48:  # RSN
                            encryption = "WPA2/WPA3"
                        elif elt.ID == 221:  # Vendor specific
                            if b'WPA' in elt.info:
                                encryption = "WPA"
                        elif elt.ID == 1:  # WEP
                            encryption = "WEP"
                
                # Only add if we have channel info or if it's a hidden network
                if channel or (ssid and ssid.strip()):
                    network_info = NetworkInfo(
                        ssid=ssid or "Hidden",
                        bssid=bssid,
                        channel=channel or 0,
                        rssi=pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -50,
                        encryption=encryption,
                        clients=[]
                    )
                    
                    with self._lock:
                        # Avoid duplicates
                        if not any(n.bssid == bssid for n in self._networks):
                            self._networks.append(network_info)
                            
        except Exception as e:
            self.logger.error(f"Error processing beacon packet: {e}")
    
    def _process_probe_response(self, pkt):
        """Process probe response packet."""
        try:
            if pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr2
                ssid = None
                channel = None
                
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode('utf-8', errors='ignore')
                                break
                            except:
                                continue
                        elif elt.ID == 3:  # Channel
                            if len(elt.info) > 0:
                                channel = elt.info[0]
                
                if ssid:
                    # Update existing network or add new one
                    with self._lock:
                        existing = next((n for n in self._networks if n.bssid == bssid), None)
                        if existing:
                            if not existing.ssid or existing.ssid == "Hidden":
                                existing.ssid = ssid
                            if channel and not existing.channel:
                                existing.channel = channel
                        else:
                            network_info = NetworkInfo(
                                ssid=ssid,
                                bssid=bssid,
                                channel=channel or 0,
                                rssi=pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -50,
                                encryption="Unknown",
                                clients=[]
                            )
                            self._networks.append(network_info)
                            
        except Exception as e:
            self.logger.error(f"Error processing probe response: {e}")
    
    def get_networks(self) -> List[NetworkInfo]:
        """Get current list of networks."""
        with self._lock:
            return self._networks.copy()
    
    def is_scanning(self) -> bool:
        """Check if currently scanning."""
        return self._scanning 