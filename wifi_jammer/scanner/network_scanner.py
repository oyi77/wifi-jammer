"""
Network scanner implementation using scapy.
"""

import time
import threading
from typing import List, Optional, Callable
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from ..core.interfaces import INetworkScanner, NetworkInfo
from ..utils.logger import RichLogger


class ScapyNetworkScanner(INetworkScanner):
    """Network scanner implementation using scapy."""
    
    def __init__(self, logger: Optional[RichLogger] = None):
        self.logger = logger or RichLogger()
        self._scanning = False
        self._networks = []
        self._lock = threading.Lock()
    
    def get_interface_list(self) -> List[str]:
        """Get list of available wireless interfaces."""
        interfaces = []
        try:
            # Get wireless interfaces
            for iface in get_if_list():
                if iface.startswith(('wlan', 'wifi', 'ath')):
                    interfaces.append(iface)
            
            # Fallback to all interfaces if no wireless found
            if not interfaces:
                interfaces = get_if_list()
                
        except Exception as e:
            self.logger.error(f"Error getting interface list: {e}")
            interfaces = []
        
        return interfaces
    
    def scan_networks(self, interface: str, channel: Optional[int] = None) -> List[NetworkInfo]:
        """Scan for available networks."""
        self._networks = []
        self._scanning = True
        
        try:
            # Set interface to monitor mode
            self._set_monitor_mode(interface)
            
            # Start scanning in background
            scan_thread = threading.Thread(
                target=self._scan_thread,
                args=(interface, channel)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
            # Wait for scan to complete
            time.sleep(5)
            self._scanning = False
            
        except Exception as e:
            self.logger.error(f"Error during network scan: {e}")
            self._scanning = False
        
        return self._networks.copy()
    
    def _scan_thread(self, interface: str, channel: Optional[int] = None):
        """Background thread for scanning networks."""
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                self._process_beacon_packet(pkt)
            elif pkt.haslayer(Dot11ProbeResp):
                self._process_probe_response(pkt)
        
        try:
            # Set channel if specified
            if channel:
                self._set_channel(interface, channel)
            
            # Start sniffing
            sniff(
                iface=interface,
                prn=packet_handler,
                store=0,
                timeout=5
            )
            
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
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        elif elt.ID == 3:  # Channel
                            channel = elt.info[0]
                
                # Determine encryption
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 48:  # RSN
                            encryption = "WPA2/WPA3"
                        elif elt.ID == 221:  # Vendor specific
                            if b'WPA' in elt.info:
                                encryption = "WPA"
                
                if ssid and channel:
                    network_info = NetworkInfo(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
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
                
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 0:  # SSID
                            ssid = elt.info.decode('utf-8', errors='ignore')
                            break
                
                if ssid:
                    # Update existing network or add new one
                    with self._lock:
                        existing = next((n for n in self._networks if n.bssid == bssid), None)
                        if existing:
                            if not existing.ssid and ssid:
                                existing.ssid = ssid
                        else:
                            network_info = NetworkInfo(
                                ssid=ssid,
                                bssid=bssid,
                                channel=0,  # Will be updated later
                                rssi=pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -50,
                                encryption="Unknown",
                                clients=[]
                            )
                            self._networks.append(network_info)
                            
        except Exception as e:
            self.logger.error(f"Error processing probe response: {e}")
    
    def _set_monitor_mode(self, interface: str):
        """Set interface to monitor mode."""
        try:
            # Check if already in monitor mode
            if "mon" in interface or "monitor" in interface:
                return
            
            # Set monitor mode using iwconfig
            os.system(f"sudo iwconfig {interface} mode monitor")
            time.sleep(1)
            
        except Exception as e:
            self.logger.error(f"Error setting monitor mode: {e}")
    
    def _set_channel(self, interface: str, channel: int):
        """Set interface channel."""
        try:
            os.system(f"sudo iwconfig {interface} channel {channel}")
            time.sleep(0.1)
        except Exception as e:
            self.logger.error(f"Error setting channel: {e}")
    
    def get_networks(self) -> List[NetworkInfo]:
        """Get current list of networks."""
        with self._lock:
            return self._networks.copy()
    
    def is_scanning(self) -> bool:
        """Check if currently scanning."""
        return self._scanning 