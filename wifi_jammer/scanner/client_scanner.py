"""Client discovery for a specific access point.

Extracted from network_scanner.py: passive sniffing that maps client
MAC addresses to last-seen timestamps for one BSSID.
"""

import re
import threading
import time
from typing import Any, Dict, Optional
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from wifi_jammer.core.interfaces import ILogger
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory, IPlatformInterface
from wifi_jammer.utils.platform_utils import get_own_mac


class ClientScanner:
    """Passive per-AP client discovery."""

    def __init__(
        self,
        logger: ILogger,
        platform_interface: Optional[IPlatformInterface] = None,
    ) -> None:
        self._logger = logger
        self.platform_interface = (
            platform_interface or PlatformInterfaceFactory.create()
        )

    def scan_clients(
        self,
        interface: str,
        ap_bssid: str,
        channel: Optional[int] = None,
        duration: int = 30,
    ) -> Dict[str, float]:
        """Scan for clients of ``ap_bssid``; returns MAC -> last-seen map."""
        my_mac = get_own_mac(interface)
        clients = {}
        clients_lock = threading.Lock()

        def packet_handler(pkt: Any) -> None:
            """Handle packets to discover clients."""
            try:
                if not pkt.haslayer(Dot11):
                    return

                # Check if packet is related to the target AP
                # addr3 is typically the BSSID in 802.11 frames
                packet_bssid = None
                if hasattr(pkt, "addr3"):
                    packet_bssid = pkt.addr3
                elif pkt.haslayer(Dot11):
                    packet_bssid = pkt[Dot11].addr3

                # Only process packets related to our target AP
                if packet_bssid and packet_bssid.lower() != ap_bssid.lower():
                    return

                current_time = time.time()

                # Extract client MAC addresses from various packet types
                client_macs = []

                # Check addr1 and addr2 (source and destination)
                for addr in [pkt.addr1, pkt.addr2]:
                    if (
                        addr
                        and addr != "ff:ff:ff:ff:ff:ff"
                        and addr.lower() != ap_bssid.lower()
                    ):
                        if not my_mac or addr.lower() != my_mac.lower():
                            client_macs.append(addr)

                # For data frames (type=2), check if it's from/to a client
                if pkt.haslayer(Dot11) and pkt.type == 2:
                    # In data frames, addr1 is receiver, addr2 is transmitter
                    # If addr2 is not the AP, it's a client
                    if (
                        hasattr(pkt, "addr2")
                        and pkt.addr2
                        and pkt.addr2.lower() != ap_bssid.lower()
                    ):
                        if not my_mac or pkt.addr2.lower() != my_mac.lower():
                            client_macs.append(pkt.addr2)

                # Update client list
                with clients_lock:
                    for mac in client_macs:
                        if mac not in clients:
                            self._logger.info(f"New client discovered: {mac}")
                        clients[mac] = current_time

            except (AttributeError, KeyError, TypeError, ValueError):
                # Silently ignore packet processing errors
                pass

        try:
            # Set interface to monitor mode if supported
            interface_info = self.platform_interface.get_interface_info(interface)
            if interface_info and interface_info.is_monitor_capable:
                if not self.platform_interface.set_monitor_mode(interface):
                    self._logger.warning(f"Could not set {interface} to monitor mode")

            # Set channel if specified
            if channel and interface_info and interface_info.is_monitor_capable:
                if not self.platform_interface.set_channel(interface, channel):
                    self._logger.warning(f"Could not set channel {channel}")

            # Start sniffing
            self._logger.info(
                f"Scanning for clients on {ap_bssid} for {duration} seconds..."
            )
            self._logger.info(
                "Tip: Generate traffic on other devices to discover them faster"
            )

            # Sniff in a separate thread to allow timeout
            def sniff_thread() -> None:
                try:
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        timeout=duration,
                        store=False,
                        quiet=True,
                    )
                except Exception as e:
                    self._logger.error(f"Error during client scanning: {e}")

            scan_thread = threading.Thread(target=sniff_thread)
            scan_thread.daemon = True
            scan_thread.start()
            scan_thread.join(timeout=duration + 5)

        except (OSError, PermissionError, RuntimeError, KeyboardInterrupt) as e:
            self._logger.error(f"Error in client scan: {e}")
            import traceback

            self._logger.debug(traceback.format_exc())

        return clients
