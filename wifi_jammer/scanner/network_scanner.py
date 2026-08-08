"""
Network scanner orchestration.

``ScapyNetworkScanner`` owns the scan lifecycle and platform dispatch,
delegating the two heavy responsibilities to focused collaborators:

* :class:`wifi_jammer.scanner.macos_scanner.MacOSScanner` — every
  macOS-only discovery/parsing/permission code path.
* :class:`wifi_jammer.scanner.packet_processor.PacketProcessor` — 802.11
  beacon/probe/data frame parsing.

All share a :class:`wifi_jammer.scanner.scan_state.ScanState` so the
mutable scan results, their lock, and the privacy counter live in one
explicit place.
"""

import os
import re
import sys
import time
import threading
import warnings
import platform as platform_system
import subprocess
from typing import List, Optional, Dict, Any

from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from wifi_jammer.core.interfaces import INetworkScanner, NetworkInfo, ILogger
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.utils.logger import RichLogger
from wifi_jammer.utils.platform_utils import is_macos
from wifi_jammer.scanner.scan_state import ScanState
from wifi_jammer.scanner.macos_scanner import MacOSScanner
from wifi_jammer.scanner.packet_processor import PacketProcessor

# Auto-install CoreWLAN on macOS if not available
_COREWLAN_AVAILABLE = False
_COREWLAN_INSTALL_ATTEMPTED = False


def _install_corewlan_if_needed() -> None:
    """Install CoreWLAN on macOS if not available."""
    global _COREWLAN_AVAILABLE, _COREWLAN_INSTALL_ATTEMPTED

    if not is_macos():
        return

    if _COREWLAN_INSTALL_ATTEMPTED:
        return

    try:
        from CoreWLAN import CWInterface, CWWiFiClient  # type: ignore[import-not-found]  # noqa: F401

        _COREWLAN_AVAILABLE = True
        return
    except ImportError:
        pass

    # Try to install automatically
    _COREWLAN_INSTALL_ATTEMPTED = True
    try:
        import subprocess as sp
        import os

        # Check if we're in a virtual environment
        venv_python = None
        if hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        ):
            # We're in a venv
            venv_python = sys.executable
        else:
            # Check for venv in common locations
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))
            venv_python_path = os.path.join(project_root, "venv", "bin", "python3")
            if os.path.exists(venv_python_path):
                venv_python = venv_python_path

        python_exe = venv_python if venv_python else sys.executable

        # Use the current Python executable to install in the correct environment
        print("🍎 Installing pyobjc-framework-CoreWLAN for macOS WiFi support...")
        print(f"   Using Python: {python_exe}")
        result = sp.run(
            [python_exe, "-m", "pip", "install", "pyobjc-framework-CoreWLAN"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print("✅ CoreWLAN installed successfully")
            # Try importing again after installation
            try:
                from CoreWLAN import CWInterface, CWWiFiClient  # noqa: F401

                _COREWLAN_AVAILABLE = True
            except ImportError as e:
                print(f"⚠️  CoreWLAN installed but import failed: {e}")
                print("   You may need to restart the script or install manually:")
                print(f"   {python_exe} -m pip install pyobjc-framework-CoreWLAN")
        else:
            print("⚠️  Failed to install CoreWLAN:")
            if result.stdout:
                print(f"   stdout: {result.stdout}")
            if result.stderr:
                print(f"   stderr: {result.stderr}")
            print(
                f"   Try installing manually: {python_exe} -m pip install pyobjc-framework-CoreWLAN"
            )
    except Exception as e:
        print(f"⚠️  Could not auto-install CoreWLAN: {e}")
        print(
            "   You can install it manually with: pip install pyobjc-framework-CoreWLAN"
        )


# Try to install on module import
_install_corewlan_if_needed()


# Suppress scapy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


class ScapyNetworkScanner(INetworkScanner):
    """Orchestrates network scanning across platforms.

    Platform dispatch (macOS vs standard), the scan lifecycle, and the
    public API live here; the macOS-specific implementation and the
    packet parsing are delegated to :class:`MacOSScanner` and
    :class:`PacketProcessor` respectively.
    """

    def __init__(self, logger: Optional[ILogger] = None):
        self.logger = logger or RichLogger()
        self._state = ScanState()
        self._platform_interface = PlatformInterfaceFactory.create()
        self._macos = MacOSScanner(
            logger=self.logger,
            state=self._state,
            corewlan_available=lambda: _COREWLAN_AVAILABLE,
            install_corewlan=_install_corewlan_if_needed,
            scapy_fallback=self._scan_standard_networks,
        )
        self._packet_processor = PacketProcessor(self.logger, self._state)
        self._macos.check_permission()

    # -- Shared state accessors (kept for API compatibility) ---------------

    @property
    def _scanning(self) -> bool:
        return self._state.scanning

    @_scanning.setter
    def _scanning(self, value: bool) -> None:
        self._state.scanning = value

    @property
    def _networks(self) -> List[NetworkInfo]:
        return self._state.networks

    @_networks.setter
    def _networks(self, value: List[NetworkInfo]) -> None:
        self._state.networks = value

    @property
    def _lock(self) -> threading.Lock:
        return self._state.lock

    @property
    def _privacy_blocked_count(self) -> int:
        return self._state.privacy_blocked_count

    @_privacy_blocked_count.setter
    def _privacy_blocked_count(self, value: int) -> None:
        self._state.privacy_blocked_count = value

    # -- macOS delegation (thin forwarders for API compatibility) ---------

    def _get_current_macos_network(self, interface: str) -> Optional[NetworkInfo]:
        """Get currently connected network information on macOS."""
        return self._macos.get_current_network(interface)

    def _get_current_macos_network_via_corewlan(
        self, interface: str
    ) -> Optional[NetworkInfo]:
        """Get current network using CoreWLAN framework."""
        return self._macos.get_current_network_via_corewlan(interface)

    def _scan_macos_networks_via_corewlan(
        self, interface: str, channel: Optional[int] = None
    ) -> int:
        """Scan for networks using CoreWLAN framework. Returns count found."""
        return self._macos.scan_via_corewlan(interface, channel)

    def _scan_macos_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> None:
        """Scan networks using macOS-specific methods."""
        self._macos.scan(interface, channel)

    # -- Public API --------------------------------------------------------

    def get_interface_list(self) -> List[str]:
        """Get list of available wireless interfaces with improved macOS diagnostics."""
        try:
            # Use platform-specific interface detection
            wireless_interfaces = self._platform_interface.get_wireless_interfaces()

            if not wireless_interfaces:
                platform_type = self._platform_interface.get_platform_type().value
                self.logger.warning(
                    f"No wireless interfaces detected on {platform_type}"
                )

                # Provide helpful diagnostics for macOS
                if platform_type == "macos":
                    self.logger.info("💡 macOS Tips:")
                    self.logger.info(
                        "   - Make sure Wi-Fi is enabled in System Settings"
                    )
                    self.logger.info(
                        "   - Try running: networksetup -listallhardwareports"
                    )
                    self.logger.info("   - Common interface names: en0, en1")

                return []

            # Return only interface names
            interface_names = [
                iface.name
                for iface in wireless_interfaces
                if iface.status == "Available"
            ]

            if not interface_names:
                self.logger.warning("No available wireless interfaces found")
                # Show which interfaces were found but not available
                unavailable = [
                    iface.name
                    for iface in wireless_interfaces
                    if iface.status != "Available"
                ]
                if unavailable:
                    self.logger.info(
                        f"Found interfaces but they are not available: {', '.join(unavailable)}"
                    )
                    if platform_system.system() == "Darwin":
                        self.logger.info("   Try: ifconfig <interface> to check status")
                return []

            # Log interface capabilities for macOS
            if is_macos():
                for iface in wireless_interfaces:
                    if iface.name in interface_names:
                        if not iface.is_monitor_capable:
                            self.logger.debug(
                                f"Interface {iface.name}: Monitor mode not supported (this is normal on macOS)"
                            )

            return interface_names

        except Exception as e:
            self.logger.error(f"Error getting interface list: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())
            return []

    def scan_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> List[NetworkInfo]:
        """Scan for available networks."""
        self._networks = []
        self._scanning = True
        self._privacy_blocked_count = 0  # Reset privacy blocked count

        try:
            # Check if interface exists and is available
            interface_info = self._platform_interface.get_interface_info(interface)
            if not interface_info or interface_info.status != "Available":
                self.logger.error(f"Interface {interface} is not available")
                self._scanning = False
                return []

            # Use platform-specific scanning
            if is_macos():
                # Ensure CoreWLAN is installed (try again if needed)
                _install_corewlan_if_needed()

                # Step 1: Try CoreWLAN network scanning first (like JamWiFi does)
                # This scans for all networks and may work even with privacy restrictions
                if _COREWLAN_AVAILABLE:
                    try:
                        self.logger.info(
                            "🔍 Scanning networks using CoreWLAN framework..."
                        )
                        corewlan_count = self._scan_macos_networks_via_corewlan(
                            interface, channel
                        )
                        if corewlan_count > 0:
                            self.logger.info(
                                f"✅ CoreWLAN scan successful, found {corewlan_count} network(s)"
                            )
                    except (ImportError, AttributeError, OSError, RuntimeError) as e:
                        self.logger.debug(
                            f"CoreWLAN scan failed: {e}, trying fallback methods..."
                        )

                # Step 2: Try to get currently connected network (may be blocked by privacy)
                try:
                    current_network = self._get_current_macos_network(interface)
                    if current_network:
                        self.logger.info(
                            f"Found current network: {current_network.ssid} ({current_network.bssid})"
                        )
                        with self._lock:
                            # Only add if not already in list
                            if not any(
                                n.bssid == current_network.bssid
                                or n.ssid == current_network.ssid
                                for n in self._networks
                            ):
                                self._networks.append(current_network)
                except (OSError, RuntimeError, AttributeError) as e:
                    self.logger.debug(f"Could not get current network: {e}")

                # Step 3: Fallback to airport/system tools if CoreWLAN didn't find enough networks
                if len(self._networks) == 0:
                    self.logger.info("Trying fallback scanning methods...")
                try:
                    self._scan_macos_networks(interface, channel)
                except (OSError, FileNotFoundError, RuntimeError) as e:
                    self.logger.warning(f"Fallback scanning methods failed: {e}")
                    # Last resort: try basic scapy scanning (only if root)
                    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
                    if is_root:
                        try:
                            self.logger.info(
                                "Attempting basic scapy-based scan (requires root)..."
                            )
                            self._scan_standard_networks(interface, channel)
                        except (OSError, PermissionError, RuntimeError) as e2:
                            self.logger.error(f"Scapy scanning also failed: {e2}")
                    else:
                        self.logger.info(
                            "💡 Tip: Run with sudo for scapy-based scanning (more accurate results)"
                        )
            else:
                # Linux/Windows scanning
                self._scan_standard_networks(interface, channel)

        except (OSError, RuntimeError, ValueError, KeyboardInterrupt) as e:
            self.logger.error(f"Error during network scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())
        finally:
            # Always ensure scanning state is reset
            self._scanning = False

        return self._networks.copy()

    def _scan_standard_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> None:
        """Standard network scanning using scapy with improved macOS support.

        Note: On macOS, this requires root privileges to access /dev/bpf0.
        """
        try:
            # Check if we have root privileges (required for /dev/bpf0 access on macOS)
            is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
            if not is_root:
                self.logger.warning(
                    "⚠️  Scapy scanning requires root privileges on macOS"
                )
                self.logger.info("   Run with sudo or use airport utility instead")
                return

            # On macOS, monitor mode is very limited, so we scan in managed mode
            # Set interface to monitor mode if supported, but don't fail if we can't
            interface_info = self._platform_interface.get_interface_info(interface)
            if interface_info:
                if interface_info.is_monitor_capable:
                    try:
                        if not self._platform_interface.set_monitor_mode(interface):
                            self.logger.debug(
                                f"Could not set {interface} to monitor mode, scanning in managed mode..."
                            )
                    except Exception as e:
                        self.logger.debug(
                            f"Monitor mode setup failed: {e}, continuing in managed mode..."
                        )
                else:
                    self.logger.debug(
                        f"Interface {interface} does not support monitor mode, scanning in managed mode..."
                    )
            else:
                self.logger.warning(f"Could not get interface info for {interface}")

            # Start scanning in background
            scan_thread = threading.Thread(
                target=self._scan_thread, args=(interface, channel)
            )
            scan_thread.daemon = True
            scan_thread.start()

            # Wait longer for scan to complete (macOS may need more time)
            # Calculate timeout: 2 seconds per channel + 10 seconds for extended scan + buffer
            channels_to_scan = (
                [channel] if channel else [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
            )
            timeout = (len(channels_to_scan) * 2) + 12
            time.sleep(min(timeout, 30))  # Cap at 30 seconds

            # Wait for thread to finish
            scan_thread.join(timeout=5)

        except PermissionError as e:
            self.logger.warning(f"⚠️  Permission denied: {e}")
            self.logger.info(
                "   Scapy requires root privileges on macOS. Run with sudo or use airport utility."
            )
        except Exception as e:
            self.logger.error(f"Error in standard network scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

    def _scan_thread(self, interface: str, channel: Optional[int] = None) -> None:
        """Background thread for scanning networks with improved macOS support."""

        def packet_handler(pkt: Any) -> None:
            self._packet_processor.handle(pkt)

        try:
            interface_info = self._platform_interface.get_interface_info(interface)
            is_macos_platform = is_macos()

            # On macOS, channel setting is limited, so we scan on current channel or all channels
            # If no specific channel, scan multiple common channels
            channels_to_scan = (
                [channel] if channel else [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
            )

            # On macOS, if monitor mode is not available, we can still scan but may get limited results
            if (
                is_macos_platform
                and interface_info
                and not interface_info.is_monitor_capable
            ):
                self.logger.debug(
                    "macOS: Scanning without monitor mode (limited functionality)"
                )
                # Just do a single extended scan without channel hopping
                try:
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        store=0,
                        timeout=10,  # Longer timeout for managed mode
                        quiet=True,
                    )
                except Exception as e:
                    self.logger.debug(f"macOS managed mode scan failed: {e}")
                return

            # Standard scanning with channel hopping (works better with monitor mode)
            for scan_channel in channels_to_scan:
                try:
                    # Set channel if supported
                    if (
                        interface_info
                        and interface_info.is_monitor_capable
                        and scan_channel
                    ):
                        try:
                            self._platform_interface.set_channel(
                                interface, scan_channel
                            )
                            time.sleep(0.2)  # Give interface time to switch channels
                        except Exception as e:
                            self.logger.debug(
                                f"Could not set channel {scan_channel}: {e}"
                            )

                    # Start sniffing - longer timeout for better results
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        store=0,
                        timeout=2,  # 2 seconds per channel
                        quiet=True,
                    )
                except Exception as e:
                    # Continue to next channel if this one fails
                    self.logger.debug(f"Channel {scan_channel} scan failed: {e}")
                    continue

            # If we still don't have networks, try a longer scan on the interface without channel hopping
            if not self._networks:
                try:
                    self.logger.debug("Performing extended scan...")
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        store=0,
                        timeout=10,
                        quiet=True,
                    )
                except Exception as e:
                    self.logger.debug(f"Extended scan failed: {e}")

        except Exception as e:
            self.logger.error(f"Error in scan thread: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

    def scan_clients(
        self,
        interface: str,
        ap_bssid: str,
        channel: Optional[int] = None,
        duration: int = 30,
    ) -> Dict[str, float]:
        """Scan for clients connected to a specific access point.

        Args:
            interface: Network interface to use
            ap_bssid: BSSID of the access point
            channel: Channel to scan on (optional)
            duration: Duration of scan in seconds

        Returns:
            Dictionary mapping client MAC addresses to last seen timestamps
        """
        clients = {}
        clients_lock = threading.Lock()

        # Get user's MAC to exclude
        try:
            result = subprocess.run(
                ["ifconfig", interface], capture_output=True, text=True, timeout=5
            )
            mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", result.stdout)
            my_mac = mac_match.group(1) if mac_match else None
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            AttributeError,
        ):
            my_mac = None

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
                            self.logger.info(f"New client discovered: {mac}")
                        clients[mac] = current_time

            except (AttributeError, KeyError, TypeError, ValueError):
                # Silently ignore packet processing errors
                pass

        try:
            # Set interface to monitor mode if supported
            interface_info = self._platform_interface.get_interface_info(interface)
            if interface_info and interface_info.is_monitor_capable:
                if not self._platform_interface.set_monitor_mode(interface):
                    self.logger.warning(f"Could not set {interface} to monitor mode")

            # Set channel if specified
            if channel and interface_info and interface_info.is_monitor_capable:
                if not self._platform_interface.set_channel(interface, channel):
                    self.logger.warning(f"Could not set channel {channel}")

            # Start sniffing
            self.logger.info(
                f"Scanning for clients on {ap_bssid} for {duration} seconds..."
            )
            self.logger.info(
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
                    self.logger.error(f"Error during client scanning: {e}")

            scan_thread = threading.Thread(target=sniff_thread)
            scan_thread.daemon = True
            scan_thread.start()
            scan_thread.join(timeout=duration + 5)

        except (OSError, PermissionError, RuntimeError, KeyboardInterrupt) as e:
            self.logger.error(f"Error in client scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

        return clients

    def get_networks(self) -> List[NetworkInfo]:
        """Get current list of networks."""
        with self._lock:
            return self._networks.copy()

    def is_scanning(self) -> bool:
        """Check if currently scanning."""
        # Use lock to ensure atomic read
        with self._lock:
            return self._scanning
