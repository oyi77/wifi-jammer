"""CoreWLAN-framework scanning for macOS.

Extracted from macos_scanner.py (Phase-2 split). Owns every CoreWLAN call:
current-network lookup and full network scans, including the privacy-blocked
count reporting consumed by the TUI.
"""

import os
import re
import subprocess
import sys

from typing import Callable, Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo
from wifi_jammer.scanner.scan_state import ScanState


class CoreWLANScanner:
    """All macOS CoreWLAN-framework code paths."""

    def __init__(
        self,
        logger: ILogger,
        state: ScanState,
        corewlan_available: Callable[[], bool],
        install_corewlan: Callable[[], None],
    ) -> None:
        self.logger = logger
        self.state = state
        self._corewlan_available = corewlan_available
        self._install_corewlan = install_corewlan

    def get_current_network_via_corewlan(self, interface: str) -> Optional[NetworkInfo]:
        """Get current network using CoreWLAN framework (requires pyobjc-framework-CoreWLAN).

        This method uses Apple's CoreWLAN framework which may work better with privacy settings.
        Automatically installs pyobjc-framework-CoreWLAN on macOS if not available.
        """
        # Try to install CoreWLAN if not available yet
        self._install_corewlan()

        # Check if CoreWLAN is available (installed at module level)
        if not self._corewlan_available():
            self.logger.debug("CoreWLAN not available, skipping CoreWLAN method")
            return None

        try:
            # Import CoreWLAN (should be available if _COREWLAN_AVAILABLE is True)
            from CoreWLAN import CWWiFiClient  # type: ignore[import-not-found]

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
            self._install_corewlan()
            # If installation succeeded, try again
            if self._corewlan_available():
                try:
                    from CoreWLAN import CWWiFiClient  # type: ignore[import-not-found]

                    return self.get_current_network_via_corewlan(interface)
                except (ImportError, AttributeError, OSError, RuntimeError):
                    pass
        except (ImportError, AttributeError, OSError) as e:
            # CoreWLAN might require permissions or might fail
            self.logger.warning(f"⚠️  CoreWLAN method failed: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

        return None

    def scan_via_corewlan(self, interface: str, channel: Optional[int] = None) -> int:
        """Scan for networks using CoreWLAN framework (like JamWiFi does).

        This method scans for all available networks using CoreWLAN's scanning API,
        which may work better than trying to get current network info.
        Returns the number of networks found.
        """
        if not self._corewlan_available():
            return 0

        try:
            from CoreWLAN import CWWiFiClient  # type: ignore[import-not-found]

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
            with self.state.lock:
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
                            if not any(n.bssid == bssid for n in self.state.networks):
                                network_info = NetworkInfo(
                                    ssid=ssid,
                                    bssid=bssid,
                                    channel=channel_number,
                                    rssi=rssi if rssi else -50,
                                    encryption=encryption,
                                    clients=[],
                                )
                                self.state.networks.append(network_info)
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
                self.state.privacy_blocked_count = network_count
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

