"""
Network scanner implementation using scapy.
"""

import os
import sys
import time
import threading
import warnings
import platform as platform_system
import subprocess
import re
from typing import List, Optional, Dict, Any
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff
from wifi_jammer.core.interfaces import (
    INetworkScanner,
    NetworkInfo,
    ILogger,
)
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.utils.logger import RichLogger
from wifi_jammer.utils.python_detector import (
    find_python_with_permission,
)
from wifi_jammer.utils.platform_utils import is_macos

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
    """Network scanner implementation using scapy."""

    def __init__(self, logger: Optional[ILogger] = None):
        self.logger = logger or RichLogger()
        self._scanning = False
        self._networks: List[NetworkInfo] = []
        self._lock = threading.Lock()
        self._platform_interface = PlatformInterfaceFactory.create()
        self._python_with_permission: Optional[str] = None
        self._privacy_blocked_count = 0  # Track networks blocked by privacy
        self._check_python_permission()

    def _check_python_permission(self) -> None:
        """Check which Python has Location Services permission and request if needed."""
        if not is_macos():
            return

        # Find Python with permission
        self._python_with_permission = find_python_with_permission()

        if (
            self._python_with_permission
            and self._python_with_permission != sys.executable
        ):
            self.logger.debug(
                f"Found Python with permission: {self._python_with_permission}"
            )
        elif not self._python_with_permission:
            # Try to request permission
            self._request_permission_if_needed()

    def _request_permission_if_needed(self) -> None:
        """Request Location Services permission if not already granted."""
        try:
            from CoreWLAN import CWWiFiClient

            client = CWWiFiClient.sharedWiFiClient()
            interface = client.interface()
            if interface:
                ssid = interface.ssid()
                if ssid:
                    # Permission already works
                    return
        except (ImportError, AttributeError, OSError):
            # CoreWLAN not available or permission denied
            pass

        # Permission not granted - try to request it
        try:
            import CoreLocation  # type: ignore[import-not-found]

            self.logger.info("🔔 Requesting Location Services permission...")
            self.logger.info("   (A dialog should appear - please click 'Allow')")

            location_manager = CoreLocation.CLLocationManager.alloc().init()
            location_manager.requestWhenInUseAuthorization()
            location_manager.startUpdatingLocation()
            time.sleep(3)
            location_manager.stopUpdatingLocation()

            # Check again after requesting
            self._python_with_permission = find_python_with_permission()
        except ImportError:
            # CoreLocation not available - user needs to grant manually
            self.logger.warning("⚠️  Location Services permission needed")
            self.logger.info("   Run: python3 tools/setup_macos.py")
            self.logger.info(
                "   Or run: bash install.sh (which runs setup automatically)"
            )
            self.logger.info("   Or grant permission manually in System Settings")
        except Exception as e:
            self.logger.debug(f"Could not request permission: {e}")

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
            # Cleanup any resources if needed
            try:
                # Reset any interface state if needed
                pass
            except (OSError, ValueError, AttributeError):
                pass

        return self._networks.copy()

    def _get_current_macos_network(self, interface: str) -> Optional[NetworkInfo]:
        """Get currently connected network information on macOS."""
        try:
            # Step 0: Try CoreWLAN framework first (most reliable, requires permissions)
            self.logger.info("🔍 Trying CoreWLAN framework for network discovery...")
            corewlan_network = self._get_current_macos_network_via_corewlan(interface)
            if corewlan_network:
                self.logger.info(
                    f"✅ CoreWLAN successfully retrieved network: {corewlan_network.ssid}"
                )
                return corewlan_network
            else:
                self.logger.debug(
                    "CoreWLAN did not return network info, trying fallback methods..."
                )

            # Step 1: Try airport -I first (gives current network info, may require sudo)
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_path):
                ap_result = subprocess.run(
                    [airport_path, interface, "-I"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if ap_result.returncode == 0 and ap_result.stdout.strip():
                    output = ap_result.stdout
                    # Extract info from airport -I output
                    ssid_match = re.search(r"^\s*SSID:\s*(.+)$", output, re.MULTILINE)
                    bssid_match = re.search(
                        r"^\s*BSSID:\s*([0-9a-fA-F:]+)$", output, re.MULTILINE
                    )
                    channel_match = re.search(
                        r"^\s*channel:\s*(\d+)", output, re.MULTILINE | re.IGNORECASE
                    )
                    rssi_match = re.search(
                        r"^\s*agrCtlRSSI:\s*(-?\d+)", output, re.MULTILINE
                    )

                    if ssid_match and bssid_match:
                        ssid = ssid_match.group(1).strip()
                        bssid = bssid_match.group(1).strip()
                        channel = int(channel_match.group(1)) if channel_match else 0
                        rssi = int(rssi_match.group(1)) if rssi_match else -50

                        # Get security from system_profiler
                        encryption = "WPA2"  # Default
                        sp_result = subprocess.run(
                            ["system_profiler", "SPAirPortDataType"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if sp_result.returncode == 0:
                            if "WPA2" in sp_result.stdout:
                                encryption = "WPA2"
                            elif "WPA" in sp_result.stdout:
                                encryption = "WPA"

                        return NetworkInfo(
                            ssid=ssid,
                            bssid=bssid,
                            channel=channel,
                            rssi=rssi,
                            encryption=encryption,
                            clients=[],
                        )

            # Step 2: Get SSID from system_profiler current network section
            ssid = None
            sp_result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if sp_result.returncode == 0:
                output = sp_result.stdout
                # Look for current network - it might show <redacted> but we can get other info
                # Check if we have an IP address (means we're connected)
                ifconfig_result = subprocess.run(
                    ["ifconfig", interface], capture_output=True, text=True, timeout=5
                )
                has_ip = (
                    "inet " in ifconfig_result.stdout
                    if ifconfig_result.returncode == 0
                    else False
                )

                if has_ip:
                    # We're connected, try to get SSID from system_profiler or other sources
                    # The current network section might have the SSID even if redacted in some tools
                    # Try networksetup first
                    ns_result = subprocess.run(
                        ["networksetup", "-getairportnetwork", interface],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if ns_result.returncode == 0:
                        ns_output = ns_result.stdout.strip()
                        if (
                            "not associated" not in ns_output.lower()
                            and ":" in ns_output
                        ):
                            ssid = ns_output.split(":")[-1].strip()

                    # If still no SSID, try to extract from system_profiler's current network
                    # Even if it says <redacted>, we might be able to infer it
                    if not ssid:
                        # Look for patterns in system_profiler that might indicate the network name
                        # Sometimes the network name appears in other sections
                        lines = output.split("\n")
                        for i, line in enumerate(lines):
                            if "Current Network Information:" in line:
                                # Look ahead for network name patterns
                                for j in range(i, min(i + 20, len(lines))):
                                    if (
                                        lines[j].strip().endswith(":")
                                        and "<redacted>" not in lines[j]
                                    ):
                                        potential_ssid = lines[j].strip().rstrip(":")
                                        if potential_ssid and len(potential_ssid) > 0:
                                            # Check if this looks like a network name (not a system field)
                                            if not any(
                                                x in potential_ssid
                                                for x in [
                                                    "PHY Mode",
                                                    "Channel",
                                                    "Country",
                                                    "Network Type",
                                                    "Security",
                                                    "Signal",
                                                    "Transmit",
                                                    "MCS",
                                                ]
                                            ):
                                                ssid = potential_ssid
                                                break
                                break

            # If we still don't have SSID but we have an IP, we're definitely connected
            # In this case, we'll need to get the network info from other sources
            if not ssid:
                # Check if we have an IP (means we're connected to something)
                ifconfig_result = subprocess.run(
                    ["ifconfig", interface], capture_output=True, text=True, timeout=5
                )
                has_ip = (
                    "inet " in ifconfig_result.stdout
                    if ifconfig_result.returncode == 0
                    else False
                )
                if not has_ip:
                    return None
                # We're connected but can't get SSID - this shouldn't happen but handle it
                ssid = "Connected Network"  # Placeholder

            # Step 2: Get network details from system_profiler (has channel, RSSI, security)
            channel = 0
            rssi = -50
            encryption = "Unknown"
            bssid = None

            sp_result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if sp_result.returncode == 0:
                output = sp_result.stdout
                lines = output.split("\n")

                # Look for "Current Network Information" section
                in_current_section = False
                for i, line in enumerate(lines):
                    line_stripped = line.strip()

                    if "Current Network Information:" in line_stripped:
                        in_current_section = True
                        continue

                    if in_current_section:
                        # Extract channel (format: "Channel: 149 (5GHz, 80MHz)")
                        if "Channel:" in line_stripped:
                            ch_match = re.search(r"Channel:\s*(\d+)", line_stripped)
                            if ch_match:
                                channel = int(ch_match.group(1))

                        # Extract RSSI/Signal (format: "Signal / Noise: -74 dBm / -94 dBm")
                        elif "Signal" in line_stripped and "dBm" in line_stripped:
                            rssi_match = re.search(
                                r"Signal[^:]*:\s*(-?\d+)\s*dBm", line_stripped
                            )
                            if rssi_match:
                                rssi = int(rssi_match.group(1))

                        # Extract Security
                        elif "Security:" in line_stripped:
                            if "WPA2" in line_stripped:
                                encryption = "WPA2"
                            elif "WPA" in line_stripped:
                                encryption = "WPA"
                            elif "WEP" in line_stripped:
                                encryption = "WEP"
                            else:
                                encryption = "Open"

                        # End of current network section
                        elif (
                            line_stripped
                            and not line_stripped.startswith(" ")
                            and ":" in line_stripped
                            and "Other" in line_stripped
                        ):
                            break

            # Step 3: Try to get BSSID from wdutil (with sudo it should give real BSSID)
            # Try both with and without sudo
            for cmd in [["wdutil", "info"], ["sudo", "wdutil", "info"]]:
                try:
                    wd_result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5
                    )
                    if wd_result.returncode == 0:
                        bssid_match = re.search(
                            r"BSSID\s+:\s+([0-9a-fA-F:]+)", wd_result.stdout
                        )
                        if bssid_match:
                            potential_bssid = bssid_match.group(1)
                            # Only use if it's not redacted and looks like a real MAC
                            if (
                                potential_bssid != "<redacted>"
                                and len(potential_bssid) == 17
                            ):
                                bssid = potential_bssid
                                # Also get channel and RSSI from wdutil if available
                                if not channel or channel == 0:
                                    ch_match = re.search(
                                        r"Channel\s+:\s+([0-9a-z/]+)", wd_result.stdout
                                    )
                                    if ch_match:
                                        ch_str = ch_match.group(1)
                                        if "g" in ch_str:
                                            channel = int(
                                                ch_str.split("g")[1].split("/")[0]
                                            )
                                        else:
                                            channel = int(ch_str.split("/")[0])
                                if not rssi or rssi == -50:
                                    rssi_match = re.search(
                                        r"RSSI\s+:\s+(-?\d+)\s*dBm", wd_result.stdout
                                    )
                                    if rssi_match:
                                        rssi = int(rssi_match.group(1))
                                break
                except (
                    subprocess.TimeoutExpired,
                    subprocess.CalledProcessError,
                    FileNotFoundError,
                    OSError,
                    ValueError,
                    AttributeError,
                ):
                    continue

            # Step 4: If we have an IP but no SSID, or if BSSID is missing, try airport scan
            # Airport scan can show networks even when system_profiler redacts them
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_path):
                ap_result = subprocess.run(
                    [airport_path, "-s"], capture_output=True, text=True, timeout=10
                )
                if (
                    ap_result.returncode == 0
                    and ap_result.stdout.strip()
                    and "WARNING" not in ap_result.stdout
                ):
                    # Parse all networks from airport scan
                    for line in ap_result.stdout.split("\n"):
                        line = line.strip()
                        if not line or "SSID" in line or "BSSID" in line:
                            continue

                        # Extract network info from airport scan line
                        # Format: SSID BSSID RSSI CHANNEL ...
                        bssid_match = re.search(
                            r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                            line,
                        )
                        if bssid_match:
                            line_bssid = bssid_match.group(1)
                            # Extract SSID (everything before the BSSID)
                            ssid_match = re.match(
                                r"^(.+?)\s+" + re.escape(line_bssid), line
                            )
                            line_ssid = (
                                ssid_match.group(1).strip() if ssid_match else None
                            )

                            # Extract RSSI and channel
                            ch_rssi_match = re.search(r"\s+(-?\d+)\s+(\d+)", line)
                            line_rssi = (
                                int(ch_rssi_match.group(1)) if ch_rssi_match else None
                            )
                            line_channel = (
                                int(ch_rssi_match.group(2)) if ch_rssi_match else None
                            )

                            # If we have a BSSID from wdutil, match by BSSID
                            if (
                                bssid
                                and bssid != "<redacted>"
                                and line_bssid.lower() == bssid.lower()
                            ):
                                if line_ssid:
                                    ssid = line_ssid
                                if line_rssi:
                                    rssi = line_rssi
                                if line_channel:
                                    channel = line_channel
                                break

                            # If we have SSID, match by SSID
                            if ssid and line_ssid and ssid.lower() == line_ssid.lower():
                                if not bssid or bssid == "<redacted>":
                                    bssid = line_bssid
                                if line_rssi:
                                    rssi = line_rssi
                                if line_channel:
                                    channel = line_channel
                                break

                            # If we don't have SSID but have channel match, this might be our network
                            if not ssid and channel > 0 and line_channel == channel:
                                ssid = line_ssid or "Connected Network"
                                if not bssid or bssid == "<redacted>":
                                    bssid = line_bssid
                                if line_rssi:
                                    rssi = line_rssi
                                break

            # Step 5: If we still don't have SSID but we're connected, create network with available info
            if not ssid or ssid == "Connected Network":
                # Check if we have an IP (means we're connected)
                ifconfig_result = subprocess.run(
                    ["ifconfig", interface], capture_output=True, text=True, timeout=5
                )
                has_ip = (
                    "inet " in ifconfig_result.stdout
                    if ifconfig_result.returncode == 0
                    else False
                )

                if has_ip and (bssid or channel > 0):
                    # We're connected but SSID is redacted - we'll need to search for it
                    # For now, return what we have and let the user specify or search
                    ssid = "Connected Network (SSID Redacted)"

            # If we have at least BSSID or channel, return the network
            if (
                bssid and bssid != "<redacted>" and bssid != "00:00:00:00:00:00"
            ) or channel > 0:
                if not bssid or bssid == "<redacted>":
                    # Can't proceed without BSSID
                    self.logger.warning(
                        "Could not get BSSID for current network (privacy settings may be blocking it)"
                    )
                    return None

                return NetworkInfo(
                    ssid=ssid or "Unknown",
                    bssid=bssid,
                    channel=channel if channel > 0 else 0,
                    rssi=rssi,
                    encryption=encryption if encryption != "Unknown" else "WPA2",
                    clients=[],
                )

        except Exception as e:
            self.logger.debug(f"Could not get current network info: {e}")

        return None

    def _get_current_macos_network_via_corewlan(
        self, interface: str
    ) -> Optional[NetworkInfo]:
        """Get current network using CoreWLAN framework (requires pyobjc-framework-CoreWLAN).

        This method uses Apple's CoreWLAN framework which may work better with privacy settings.
        Automatically installs pyobjc-framework-CoreWLAN on macOS if not available.
        """
        # Try to install CoreWLAN if not available yet
        _install_corewlan_if_needed()

        # Check if CoreWLAN is available (installed at module level)
        if not _COREWLAN_AVAILABLE:
            self.logger.debug("CoreWLAN not available, skipping CoreWLAN method")
            return None

        try:
            # Import CoreWLAN (should be available if _COREWLAN_AVAILABLE is True)
            from CoreWLAN import CWWiFiClient

            self.logger.debug("Attempting to get network info via CoreWLAN...")

            wifi_client = CWWiFiClient.sharedWiFiClient()
            interface_obj = wifi_client.interfaceWithName_(interface)

            if not interface_obj:
                # Try to get default interface
                interface_obj = wifi_client.interface()

            if interface_obj:
                # Check if interface is associated/connected
                power_on = interface_obj.powerOn()
                associated = interface_obj.serviceActive()

                self.logger.debug(
                    f"CoreWLAN interface power: {power_on}, associated: {associated}"
                )

                if not power_on:
                    self.logger.debug("CoreWLAN: WiFi interface is not powered on")
                    return None

                if not associated:
                    self.logger.debug(
                        "CoreWLAN: Interface is not associated with a network"
                    )
                    return None

                # Try to get network information
                ssid = interface_obj.ssid()
                bssid = interface_obj.bssid()
                rssi = interface_obj.rssiValue()

                self.logger.debug(
                    f"CoreWLAN raw values - SSID: {ssid}, BSSID: {bssid}, RSSI: {rssi}"
                )

                # If SSID is None, it's likely blocked by privacy settings
                # CoreWLAN requires Location Services permission to access SSID/BSSID

                # Get channel information
                channel_obj = interface_obj.wlanChannel()
                channel_number = channel_obj.channelNumber() if channel_obj else 0

                # Get security information
                encryption = "Unknown"
                try:
                    security = interface_obj.security()
                    if security:
                        # Security is a bitmask, check for common types
                        # These constants might vary, so we check the value
                        security_value = int(security)
                        if security_value & 0x4:  # WPA2
                            encryption = "WPA2"
                        elif security_value & 0x2:  # WPA
                            encryption = "WPA"
                        elif security_value & 0x1:  # WEP
                            encryption = "WEP"
                        else:
                            encryption = "Open"
                except (AttributeError, TypeError, ValueError):
                    encryption = "WPA2"  # Default assumption

                if ssid and bssid:
                    self.logger.info(
                        f"✅ CoreWLAN found network: {ssid} ({bssid}) on channel {channel_number}"
                    )
                    return NetworkInfo(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel_number,
                        rssi=rssi if rssi else -50,  # Default RSSI if None
                        encryption=encryption if encryption != "Unknown" else "WPA2",
                        clients=[],
                    )
                else:
                    # SSID/BSSID are None - this is a privacy settings issue
                    # CoreWLAN requires Location Services permission to access network info
                    self.logger.warning(
                        "⚠️  CoreWLAN: SSID/BSSID are None - privacy settings are blocking access"
                    )
                    self.logger.info("")
                    self.logger.info("🔧 QUICK FIX:")
                    self.logger.info("   Run: python3 fix_location_permission.py")
                    self.logger.info("")
                    self.logger.info("📋 Or manually:")
                    self.logger.info(
                        "   1. System Settings → Privacy & Security → Location Services"
                    )
                    self.logger.info("   2. Enable Location Services (toggle ON)")
                    self.logger.info(
                        "   3. Find 'Terminal' or 'Python' and check the box ✅"
                    )
                    self.logger.debug("   Falling back to other methods...")
                    return None
            else:
                self.logger.debug("CoreWLAN: Could not get interface object")
        except ImportError as e:
            # pyobjc-framework-CoreWLAN not installed - this is optional
            self.logger.warning(f"⚠️  CoreWLAN not available: {e}")
            self.logger.info("   Attempting to install CoreWLAN...")
            # Try to install it
            _install_corewlan_if_needed()
            # If installation succeeded, try again
            if _COREWLAN_AVAILABLE:
                try:
                    from CoreWLAN import CWWiFiClient

                    return self._get_current_macos_network_via_corewlan(interface)
                except (ImportError, AttributeError, OSError, RuntimeError):
                    pass
        except (ImportError, AttributeError, OSError) as e:
            # CoreWLAN might require permissions or might fail
            self.logger.warning(f"⚠️  CoreWLAN method failed: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

        return None

    def _scan_macos_networks_via_corewlan(
        self, interface: str, channel: Optional[int] = None
    ) -> int:
        """Scan for networks using CoreWLAN framework (like JamWiFi does).

        This method scans for all available networks using CoreWLAN's scanning API,
        which may work better than trying to get current network info.
        Returns the number of networks found.
        """
        if not _COREWLAN_AVAILABLE:
            return 0

        try:
            from CoreWLAN import CWWiFiClient

            self.logger.debug("Scanning networks using CoreWLAN...")

            wifi_client = CWWiFiClient.sharedWiFiClient()
            interface_obj = wifi_client.interfaceWithName_(interface)

            if not interface_obj:
                interface_obj = wifi_client.interface()

            if not interface_obj:
                self.logger.debug("CoreWLAN: Could not get interface")
                return 0

            # Scan for all networks (passing None scans for all)
            # The method returns a tuple: (networks, error)
            # networks is an NSSet (Objective-C set), not a Python list
            networks_set = None
            network_count = 0
            try:
                result = interface_obj.scanForNetworksWithName_error_(None, None)
                # Handle tuple return: (networks, error)
                if isinstance(result, tuple):
                    networks_set, error = result
                    if error is not None:
                        error_msg = str(error) if error else "Unknown error"
                        self.logger.debug(f"CoreWLAN scan error: {error_msg}")
                        return 0
                else:
                    # Some versions might return just the networks
                    networks_set = result

                # Convert NSSet to Python list for iteration
                # NSSet objects can be iterated directly, but we need to check if it's empty
                if networks_set is None:
                    self.logger.debug("CoreWLAN scan returned None")
                    return 0

                # Get count to check if set is empty (NSSet doesn't support len() directly)
                try:
                    network_count = networks_set.count()
                    if network_count == 0:
                        self.logger.debug("CoreWLAN scan returned empty set")
                        return 0
                except (AttributeError, TypeError):
                    # If count() doesn't work, try to iterate and count manually
                    network_count = 0
                    try:
                        for _ in networks_set:
                            network_count += 1
                    except (TypeError, AttributeError, RuntimeError):
                        pass
                    if network_count == 0:
                        self.logger.debug("CoreWLAN scan returned no networks")
                        return 0
            except Exception as e:
                self.logger.debug(f"CoreWLAN scan exception: {e}")
                import traceback

                self.logger.debug(traceback.format_exc())
                return 0

            networks_found = 0
            with self._lock:
                # Iterate over the NSSet
                for network in networks_set:
                    try:
                        # Get network properties - handle both CWNetwork objects and other types
                        if not hasattr(network, "ssid"):
                            continue

                        ssid = network.ssid()
                        bssid = network.bssid()
                        rssi = (
                            network.rssiValue()
                            if hasattr(network, "rssiValue")
                            else -50
                        )

                        # Get channel
                        wlan_channel = (
                            network.wlanChannel()
                            if hasattr(network, "wlanChannel")
                            else None
                        )
                        channel_number = (
                            wlan_channel.channelNumber() if wlan_channel else 0
                        )

                        # Get security/encryption
                        encryption = "WPA2"  # Default
                        if hasattr(network, "security"):
                            try:
                                security = network.security()
                                if security:
                                    security_value = int(security)
                                    if security_value & 0x4:  # WPA2
                                        encryption = "WPA2"
                                    elif security_value & 0x2:  # WPA
                                        encryption = "WPA"
                                    elif security_value & 0x1:  # WEP
                                        encryption = "WEP"
                                    else:
                                        encryption = "Open"
                            except (AttributeError, TypeError, ValueError):
                                pass

                        # Only add if we have SSID and BSSID
                        if ssid and bssid:
                            # Check if network already exists
                            if not any(n.bssid == bssid for n in self._networks):
                                network_info = NetworkInfo(
                                    ssid=ssid,
                                    bssid=bssid,
                                    channel=channel_number,
                                    rssi=rssi if rssi else -50,
                                    encryption=encryption,
                                    clients=[],
                                )
                                self._networks.append(network_info)
                                networks_found += 1
                                self.logger.debug(
                                    f"CoreWLAN found: {ssid} ({bssid}) on channel {channel_number}"
                                )
                        else:
                            # Network found but SSID/BSSID are None (privacy restrictions)
                            self.logger.debug(
                                f"CoreWLAN: Network found on channel {channel_number} but SSID/BSSID are blocked by privacy settings"
                            )
                    except Exception as e:
                        # Skip networks that can't be accessed (privacy restrictions or invalid objects)
                        self.logger.debug(f"CoreWLAN: Skipping network object: {e}")
                        continue

            if networks_found > 0:
                self.logger.info(f"✅ CoreWLAN scan found {networks_found} network(s)")
            elif network_count > 0:
                # Networks were found but couldn't be processed due to privacy settings
                # Store this info so TUI can display it
                self._privacy_blocked_count = network_count
                self.logger.warning(
                    f"⚠️  CoreWLAN found {network_count} network(s) but SSID/BSSID are blocked by privacy settings"
                )
                self.logger.info("")
                self.logger.info("🔧 QUICK FIX:")
                self.logger.info("   Run: bash install.sh")
                self.logger.info("   Or: python3 tools/setup_macos.py")
                self.logger.info("")
                self.logger.info("📋 Or manually:")
                self.logger.info(
                    "   1. System Settings → Privacy & Security → Location Services"
                )
                self.logger.info("   2. Enable Location Services (toggle ON)")
                self.logger.info(
                    f"   3. Find '{os.path.basename(sys.executable)}' or 'Terminal' and check the box ✅"
                )

            return networks_found

        except ImportError:
            self.logger.debug("CoreWLAN not available for scanning")
            return 0
        except Exception as e:
            self.logger.debug(f"CoreWLAN scan error: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())
            return 0

    def _scan_macos_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> None:
        """Scan networks using macOS-specific methods with improved error handling."""
        try:
            # Check if we're running as root
            is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

            # Method 1: Try wdutil first (modern replacement for airport, may require root for full scan)
            # wdutil scan works better than airport on newer macOS
            try:
                self.logger.info("Scanning using wdutil (modern macOS WiFi tool)...")
                # Try without sudo first
                wd_cmd = ["wdutil", "scan"]
                result = subprocess.run(
                    wd_cmd, capture_output=True, text=True, timeout=15
                )

                # If that fails, try with sudo if we have root
                if result.returncode != 0 and is_root:
                    wd_cmd = ["sudo", "wdutil", "scan"]
                    result = subprocess.run(
                        wd_cmd, capture_output=True, text=True, timeout=15
                    )

                if result.returncode == 0 and result.stdout.strip():
                    # Parse wdutil output (format may vary)
                    networks_found = self._parse_wdutil_scan(result.stdout)
                    if networks_found > 0:
                        self.logger.info(f"✅ wdutil found {networks_found} network(s)")
                        return
            except FileNotFoundError:
                self.logger.debug("wdutil not found, trying other methods...")
            except Exception as e:
                self.logger.debug(f"wdutil failed: {e}")

            # Method 2: Try airport utility (deprecated but may still work)
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_path):
                try:
                    self.logger.info("Scanning using macOS airport utility...")
                    # Airport -s works without root for scanning
                    api_cmd = [airport_path, "-s"]
                    result = subprocess.run(
                        api_cmd, capture_output=True, text=True, timeout=15
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        # Check if output contains actual network data
                        # Airport may show deprecation warnings but still work
                        output_lines = result.stdout.split("\n")
                        has_networks = False
                        for line in output_lines:
                            # Look for lines with BSSID pattern (XX:XX:XX:XX:XX:XX)
                            if re.search(
                                r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}",
                                line,
                            ):
                                has_networks = True
                                break

                        if has_networks:
                            networks_found = self._parse_airport_scan(result.stdout)
                            if networks_found > 0:
                                self.logger.info(
                                    f"✅ Airport utility found {networks_found} network(s)"
                                )
                                return
                        else:
                            self.logger.debug(
                                "Airport utility returned no network data (may be deprecated)"
                            )
                except subprocess.TimeoutExpired:
                    self.logger.debug("Airport utility timed out")
                except Exception as e:
                    self.logger.debug(f"Airport utility failed: {e}")

            # Method 3: Use system_profiler (works without root, but limited info)
            if not self._networks:
                try:
                    self.logger.info("Trying system_profiler as fallback...")
                    result = subprocess.run(
                        ["system_profiler", "SPAirPortDataType"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    if result.returncode == 0:
                        self._parse_macos_networks(result.stdout)
                        if len(self._networks) > 0:
                            self.logger.info(
                                f"✅ system_profiler found {len(self._networks)} network(s)"
                            )
                            return
                except Exception as e:
                    self.logger.debug(f"system_profiler failed: {e}")

            # Method 4: Try scapy scanning only if we have root (requires /dev/bpf0 access)
            if is_root:
                try:
                    self.logger.info(
                        "Using scapy-based network scanning (running as root)..."
                    )
                    self._scan_standard_networks(interface, channel)
                    if len(self._networks) > 0:
                        return
                except Exception as e:
                    self.logger.debug(f"Scapy scanning failed: {e}")
            else:
                # Show helpful message if no networks found and not running as root
                if not self._networks:
                    self.logger.warning("⚠️  No networks found with current methods")
                    self.logger.info("💡 Try running with sudo for better results:")
                    self.logger.info("   sudo python -m wifi_jammer.cli scan")
                    self.logger.info(
                        "   This enables scapy-based scanning (more accurate)"
                    )

        except Exception as e:
            self.logger.error(f"Error in macOS network scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

    def _parse_wdutil_scan(self, output: str) -> int:
        """Parse wdutil scan output. Returns number of networks found."""
        networks_found = 0
        try:
            # wdutil output format varies, try to parse common patterns
            lines = output.split("\n")

            current_network: Dict[str, Any] = {}
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Look for SSID
                ssid_match = re.search(r"SSID\s*:\s*(.+)", line, re.IGNORECASE)
                if ssid_match:
                    current_network["ssid"] = ssid_match.group(1).strip()

                # Look for BSSID
                bssid_match = re.search(
                    r"BSSID\s*:\s*([0-9a-fA-F:]+)", line, re.IGNORECASE
                )
                if bssid_match:
                    bssid = bssid_match.group(1).strip()
                    if re.match(
                        r"^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$",
                        bssid,
                    ):
                        current_network["bssid"] = bssid

                # Look for Channel
                channel_match = re.search(r"Channel\s*:\s*(\d+)", line, re.IGNORECASE)
                if channel_match:
                    current_network["channel"] = int(channel_match.group(1))

                # Look for RSSI
                rssi_match = re.search(r"RSSI\s*:\s*(-?\d+)", line, re.IGNORECASE)
                if rssi_match:
                    current_network["rssi"] = int(rssi_match.group(1))

                # Look for Security
                if "WPA2" in line.upper():
                    current_network["encryption"] = "WPA2"
                elif "WPA" in line.upper():
                    current_network["encryption"] = "WPA"
                elif "WEP" in line.upper():
                    current_network["encryption"] = "WEP"
                elif "security" in line.lower() and "none" in line.lower():
                    current_network["encryption"] = "Open"

                # If we have SSID and BSSID, create network info
                if "ssid" in current_network and "bssid" in current_network:
                    network_info = NetworkInfo(
                        ssid=current_network.get("ssid", "Unknown"),
                        bssid=current_network["bssid"],
                        channel=current_network.get("channel", 0),
                        rssi=current_network.get("rssi", -50),
                        encryption=current_network.get("encryption", "Unknown"),
                        clients=[],
                    )

                    with self._lock:
                        if not any(
                            n.bssid == network_info.bssid for n in self._networks
                        ):
                            self._networks.append(network_info)
                            networks_found += 1
                            self.logger.debug(
                                f"wdutil found: {network_info.ssid} ({network_info.bssid})"
                            )

                    current_network = {}
        except Exception as e:
            self.logger.debug(f"Error parsing wdutil scan: {e}")

        return networks_found

    def _parse_airport_scan(self, output: str) -> int:
        """Parse airport -s output. Returns number of networks found."""
        networks_found = 0
        try:
            lines = output.split("\n")
            if not lines:
                return 0

            # Skip header line and any warning lines
            for line in lines[1:]:
                line = line.strip()
                if not line or "WARNING" in line or "deprecated" in line.lower():
                    continue

                # Airport output format: SSID BSSID RSSI CHANNEL HT CC SECURITY
                # Example: "KOST BERLIAN    10:8f:fe:00:a3:e0  -77  149  Y  --  WPA2(PSK/AES/AES)"
                # Use regex to parse - BSSID is always 17 chars (XX:XX:XX:XX:XX:XX)
                # Look for pattern: text, then BSSID, then RSSI (negative number), then channel
                match = re.search(
                    r"^(.+?)\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\s+(-?\d+)\s+(\d+)",
                    line,
                )
                if match:
                    ssid = match.group(1).strip()
                    bssid = match.group(2).strip()
                    rssi = int(match.group(3))
                    channel = int(match.group(4))

                    # Extract security from the rest of the line
                    security_part = line[match.end() :].strip()
                    encryption = "Open"
                    if "WPA2" in security_part or "WPA2" in line:
                        encryption = "WPA2"
                    elif "WPA" in security_part or "WPA" in line:
                        encryption = "WPA"
                    elif "WEP" in security_part or "WEP" in line:
                        encryption = "WEP"

                    # Validate BSSID format
                    if not re.match(
                        r"^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$",
                        bssid,
                    ):
                        continue

                    network_info = NetworkInfo(
                        ssid=ssid or "Hidden",
                        bssid=bssid,
                        channel=channel,
                        rssi=rssi,
                        encryption=encryption,
                        clients=[],
                    )

                    with self._lock:
                        if not any(n.bssid == bssid for n in self._networks):
                            self._networks.append(network_info)
                            networks_found += 1
                            self.logger.debug(
                                f"Airport found: {ssid} ({bssid}) on channel {channel}"
                            )
        except Exception as e:
            self.logger.error(f"Error parsing airport scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

        return networks_found

    def _parse_macos_networks(self, output: str) -> None:
        """Parse macOS system_profiler output to extract network information."""
        try:
            lines = output.split("\n")

            # First, look for "Current Network Information" section which has real BSSID
            in_current_network = False
            current_network_data: Dict[str, Any] = {}

            for i, line in enumerate(lines):
                line_stripped = line.strip()

                # Look for current network section
                if (
                    "Current Network Information:" in line_stripped
                    or "Current Network:" in line_stripped
                ):
                    in_current_network = True
                    continue

                if in_current_network:
                    # Extract current network info
                    if "Network Name:" in line_stripped or "SSID:" in line_stripped:
                        current_network_data["ssid"] = line_stripped.split(":")[
                            -1
                        ].strip()
                    elif "BSSID:" in line_stripped:
                        bssid = line_stripped.split(":")[-1].strip()
                        if bssid and bssid != "<redacted>":
                            current_network_data["bssid"] = bssid
                    elif "Channel:" in line_stripped:
                        ch_match = re.search(r"Channel:\s*(\d+)", line_stripped)
                        if ch_match:
                            current_network_data["channel"] = int(ch_match.group(1))
                    elif "Signal:" in line_stripped or "RSSI:" in line_stripped:
                        rssi_match = re.search(r"(-?\d+)\s*dBm", line_stripped)
                        if rssi_match:
                            current_network_data["rssi"] = int(rssi_match.group(1))
                    elif "Security:" in line_stripped:
                        if "WPA2" in line_stripped:
                            current_network_data["encryption"] = "WPA2"
                        elif "WPA" in line_stripped:
                            current_network_data["encryption"] = "WPA"
                        elif "WEP" in line_stripped:
                            current_network_data["encryption"] = "WEP"
                        else:
                            current_network_data["encryption"] = "Open"
                    elif (
                        line_stripped
                        and not line_stripped.startswith(" ")
                        and ":" in line_stripped
                    ):
                        # End of current network section
                        if current_network_data.get(
                            "ssid"
                        ) and current_network_data.get("bssid"):
                            network_info = NetworkInfo(
                                ssid=str(current_network_data.get("ssid", "Unknown")),
                                bssid=str(current_network_data.get("bssid", "")),
                                channel=int(current_network_data.get("channel", 0)),
                                rssi=int(current_network_data.get("rssi", -50)),
                                encryption=str(
                                    current_network_data.get("encryption", "Unknown")
                                ),
                                clients=[],
                            )
                            with self._lock:
                                if not any(
                                    n.bssid == network_info.bssid
                                    for n in self._networks
                                ):
                                    self._networks.append(network_info)
                            current_network_data = {}
                            in_current_network = False
                        break

            # Also look for "Other Local Wi-Fi Networks:" section
            in_networks_section = False

            for i, line in enumerate(lines):
                line = line.strip()

                # Check if we're entering the networks section
                if "Other Local Wi-Fi Networks:" in line:
                    in_networks_section = True
                    continue

                # If we're in the networks section, look for network names
                if in_networks_section:
                    # Skip empty lines and section headers
                    if (
                        not line
                        or line.startswith("Wi-Fi:")
                        or line.startswith("Interfaces:")
                    ):
                        continue

                    # Check if this line looks like a network name (ends with ':')
                    if line.endswith(":") and not any(
                        keyword in line
                        for keyword in [
                            "Card Type",
                            "Firmware",
                            "MAC Address",
                            "Supported",
                            "Wake On",
                            "AirDrop",
                            "Auto Unlock",
                            "Status",
                            "Current Network",
                            "Other Local",
                            "Software Versions",
                        ]
                    ):
                        network_name = line[:-1].strip()  # Remove the colon
                        if network_name:
                            # Extract network info from the next few lines
                            parsed_network = self._extract_macos_network_info(lines, i)
                            if parsed_network:
                                with self._lock:
                                    if not any(
                                        n.ssid == network_name for n in self._networks
                                    ):
                                        self._networks.append(parsed_network)

                # Stop parsing if we hit another major section
                elif in_networks_section and line.startswith("awdl0:"):
                    break

        except Exception as e:
            self.logger.error(f"Error parsing macOS networks: {e}")

    def _extract_macos_network_info(
        self, lines: List[str], start_index: int
    ) -> Optional[NetworkInfo]:
        """Extract network information from macOS system_profiler output."""
        try:
            network_name = lines[start_index].split(":")[0].strip()
            channel = 0
            encryption = "Unknown"
            rssi = -50

            # Look for network details in the next few lines
            for i in range(start_index + 1, min(start_index + 15, len(lines))):
                line = lines[i].strip()

                # Stop if we hit another network or section
                if line.endswith(":") and not any(
                    keyword in line
                    for keyword in [
                        "PHY Mode",
                        "Channel",
                        "Security",
                        "Signal",
                        "Network Type",
                    ]
                ):
                    break

                if "Channel:" in line:
                    # Extract channel number
                    channel_match = re.search(r"Channel:\s*(\d+)", line)
                    if channel_match:
                        channel = int(channel_match.group(1))

                elif "Security:" in line:
                    # Extract encryption type
                    if "WPA2" in line:
                        encryption = "WPA2"
                    elif "WPA" in line:
                        encryption = "WPA"
                    elif "WEP" in line:
                        encryption = "WEP"
                    else:
                        encryption = "Open"

                elif "Signal" in line and "dBm" in line:
                    # Extract signal strength
                    rssi_match = re.search(r"(-?\d+)\s*dBm", line)
                    if rssi_match:
                        rssi = int(rssi_match.group(1))

                elif line.startswith("Network Type:") or line.startswith("PHY Mode:"):
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
                clients=[],
            )

        except Exception as e:
            self.logger.error(f"Error extracting network info: {e}")
            return None

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
            try:
                if pkt.haslayer(Dot11Beacon):
                    self._process_beacon_packet(pkt)
                elif pkt.haslayer(Dot11ProbeResp):
                    self._process_probe_response(pkt)
                elif pkt.haslayer(Dot11) and pkt.type == 2:
                    # Also process data frames (type=2) to detect clients
                    self._process_data_packet(pkt)
            except (AttributeError, KeyError, TypeError, ValueError):
                # Silently ignore packet processing errors
                pass

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

    def _process_beacon_packet(self, pkt: Any) -> None:
        """Process beacon packet to extract network info."""
        try:
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                ssid = None
                channel = None
                encryption = "Unknown"
                clients: List[str] = []

                # Extract SSID
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode("utf-8", errors="ignore")
                            except (UnicodeDecodeError, AttributeError, TypeError):
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
                            if b"WPA" in elt.info:
                                encryption = "WPA"
                        elif elt.ID == 1:  # WEP
                            encryption = "WEP"

                # Only add if we have channel info or if it's a hidden network
                if channel or (ssid and ssid.strip()):
                    network_info = NetworkInfo(
                        ssid=ssid or "Hidden",
                        bssid=bssid,
                        channel=channel or 0,
                        rssi=(
                            pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -50
                        ),
                        encryption=encryption,
                        clients=clients,
                    )

                    with self._lock:
                        # Update existing network or add new one
                        existing = next(
                            (n for n in self._networks if n.bssid == bssid), None
                        )
                        if existing is not None:
                            # Update existing network info
                            if not existing.ssid or existing.ssid == "Hidden":
                                existing.ssid = network_info.ssid
                            if not existing.channel and network_info.channel:
                                existing.channel = network_info.channel
                            if (
                                network_info.rssi is not None
                                and existing.rssi is not None
                            ):
                                if (
                                    network_info.rssi > existing.rssi
                                ):  # Update with better signal
                                    existing.rssi = network_info.rssi
                            elif network_info.rssi is not None:
                                existing.rssi = network_info.rssi
                            if network_info.encryption != "Unknown":
                                existing.encryption = network_info.encryption
                        else:
                            self._networks.append(network_info)

        except Exception as e:
            self.logger.error(f"Error processing beacon packet: {e}")

    def _process_probe_response(self, pkt: Any) -> None:
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
                                ssid = elt.info.decode("utf-8", errors="ignore")
                                break
                            except (UnicodeDecodeError, AttributeError, TypeError):
                                continue
                        elif elt.ID == 3:  # Channel
                            if len(elt.info) > 0:
                                channel = elt.info[0]

                if ssid:
                    # Update existing network or add new one
                    with self._lock:
                        existing = next(
                            (n for n in self._networks if n.bssid == bssid), None
                        )
                        if existing is not None:
                            if not existing.ssid or existing.ssid == "Hidden":
                                existing.ssid = ssid
                            if channel and not existing.channel:
                                existing.channel = channel
                        else:
                            network_info = NetworkInfo(
                                ssid=ssid,
                                bssid=bssid,
                                channel=channel or 0,
                                rssi=(
                                    pkt.dBm_AntSignal
                                    if hasattr(pkt, "dBm_AntSignal")
                                    else -50
                                ),
                                encryption="Unknown",
                                clients=[],
                            )
                            self._networks.append(network_info)

        except Exception as e:
            self.logger.error(f"Error processing probe response: {e}")

    def _process_data_packet(self, pkt: Any) -> None:
        """Process data packet to detect clients."""
        try:
            # Check if it's a data frame (type=2 in 802.11)
            if not pkt.haslayer(Dot11) or pkt.type != 2:
                return

            # Extract BSSID from data frame (addr3)
            if not hasattr(pkt, "addr3") or not pkt.addr3:
                return

            bssid = pkt.addr3

            # Extract client MAC addresses
            # In data frames:
            # - addr1: Receiver (could be AP or client)
            # - addr2: Transmitter (could be AP or client)
            # - addr3: BSSID (AP MAC)
            # - addr4: Only in WDS mode

            client_macs = []

            # Check addr1 and addr2 for client MACs
            for addr in [pkt.addr1, pkt.addr2]:
                if (
                    addr
                    and addr != "ff:ff:ff:ff:ff:ff"
                    and addr.lower() != bssid.lower()
                ):
                    # This is likely a client MAC
                    client_macs.append(addr)

            # Update network's client list
            if client_macs:
                with self._lock:
                    network = next(
                        (n for n in self._networks if n.bssid == bssid), None
                    )
                    if network is not None:
                        # Initialize clients list if needed
                        if network.clients is None:
                            network.clients = []

                        # Add new clients (avoid duplicates)
                        for mac in client_macs:
                            if mac and mac not in network.clients:
                                network.clients.append(mac)
                                # Limit client list size to prevent memory issues
                                if len(network.clients) > 100:
                                    network.clients = network.clients[-100:]

        except (AttributeError, KeyError, TypeError, ValueError):
            # Silently ignore data packet processing errors
            pass

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
