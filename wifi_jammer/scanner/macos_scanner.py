"""macOS-specific scanning orchestration.

Phase-2 split of the former 1277-line module: this is now a thin facade.
Collaborators own the platform-specific code paths:

* :class:`~wifi_jammer.scanner.macos_permissions.MacOSPermissions` —
  Location Services permission detection/request.
* :class:`~wifi_jammer.scanner.macos_corewlan.CoreWLANScanner` — every
  CoreWLAN-framework call.
* :class:`~wifi_jammer.scanner.macos_systools.MacOSSystemTools` —
  wdutil/airport/system_profiler discovery and parsing.

The public API of ``MacOSScanner`` is unchanged; ``ScapyNetworkScanner``
continues to construct it exactly as before.
"""

import os
from typing import Callable, Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo
from wifi_jammer.scanner.scan_state import ScanState
from wifi_jammer.scanner.macos_permissions import MacOSPermissions
from wifi_jammer.scanner.macos_corewlan import CoreWLANScanner
from wifi_jammer.scanner.macos_systools import MacOSSystemTools
from wifi_jammer.scanner.macos_sp_parsers import SystemProfilerParsers


class MacOSScanner:
    """Facade coordinating macOS-specific discovery collaborators."""

    def __init__(
        self,
        logger: ILogger,
        state: ScanState,
        corewlan_available: Callable[[], bool],
        install_corewlan: Callable[[], None],
        scapy_fallback: Callable[[str, Optional[int]], None],
    ) -> None:
        self.logger = logger
        self.state = state
        self._corewlan_available = corewlan_available
        self._install_corewlan = install_corewlan
        self._scapy_fallback = scapy_fallback

        self._permissions = MacOSPermissions(self.logger)
        self._corewlan = CoreWLANScanner(
            logger=self.logger,
            state=self.state,
            corewlan_available=corewlan_available,
            install_corewlan=install_corewlan,
        )
        self._systools = MacOSSystemTools(
            logger=self.logger,
            state=self.state,
            scapy_fallback=scapy_fallback,
        )
        self._sp = SystemProfilerParsers(logger=self.logger, state=self.state)

    # -- Permissions ------------------------------------------------------

    def check_permission(self) -> None:
        """Check which Python has Location Services permission."""
        self._permissions.check_permission()

    # -- Current network --------------------------------------------------

    def get_current_network(self, interface: str) -> Optional[NetworkInfo]:
        """Get currently connected network information on macOS."""
        try:
            self.logger.info("🔍 Trying CoreWLAN framework for network discovery...")
            corewlan_network = self._corewlan.get_current_network_via_corewlan(
                interface
            )
            if corewlan_network:
                self.logger.info(
                    f"✅ CoreWLAN successfully retrieved network: "
                    f"{corewlan_network.ssid}"
                )
                return corewlan_network
            self.logger.debug(
                "CoreWLAN did not return network info, trying fallback methods..."
            )
        except (AttributeError, OSError) as e:
            self.logger.debug(f"Could not get current network info: {e}")
        from wifi_jammer.scanner.macos_current_network import (
            find_current_network as _find_current,
        )

        return _find_current(self.logger, interface)

    def get_current_network_via_corewlan(
        self, interface: str
    ) -> Optional[NetworkInfo]:
        """Get current network using the CoreWLAN framework."""
        return self._corewlan.get_current_network_via_corewlan(interface)

    # -- Scanning ---------------------------------------------------------

    def scan_via_corewlan(
        self, interface: str, channel: Optional[int] = None
    ) -> int:
        """Scan for networks using CoreWLAN. Returns count found."""
        return self._corewlan.scan_via_corewlan(interface, channel)

    def scan(self, interface: str, channel: Optional[int] = None) -> None:
        """Scan networks using macOS system tools with scapy fallback."""
        self._systools.scan(interface, channel)

    @property
    def _networks(self):
        return self.state.networks

    @_networks.setter
    def _networks(self, value):
        self.state.networks = value

    @property
    def _lock(self):
        return self.state.lock



    # -- Scan orchestration (moved verbatim from ScapyNetworkScanner) ------

    def scan_networks(self, interface: str, channel=None) -> None:
        """CoreWLAN-first discovery with system-tool fallbacks."""
        # Ensure CoreWLAN is installed (try again if needed)
        self._install_corewlan()

        # Step 1: Try CoreWLAN network scanning first (like JamWiFi does)
        # This scans for all networks and may work even with privacy restrictions
        if self._corewlan_available():
            try:
                self.logger.info(
                    "🔍 Scanning networks using CoreWLAN framework..."
                )
                corewlan_count = self.scan_via_corewlan(
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
            current_network = self.get_current_network(interface)
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
            self.scan(interface, channel)
        except (OSError, FileNotFoundError, RuntimeError) as e:
            self.logger.warning(f"Fallback scanning methods failed: {e}")
            # Last resort: try basic scapy scanning (only if root)
            is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
            if is_root:
                try:
                    self.logger.info(
                        "Attempting basic scapy-based scan (requires root)..."
                    )
                    self._scapy_fallback(interface, channel)
                except (OSError, PermissionError, RuntimeError) as e2:
                    self.logger.error(f"Scapy scanning also failed: {e2}")
            else:
                self.logger.info(
                    "💡 Tip: Run with sudo for scapy-based scanning (more accurate results)"
                )


    # -- Parsing (delegated, fixture-covered) ------------------------------

    def parse_wdutil_scan(self, output: str) -> int:
        """Parse wdutil scan output. Returns number of networks found."""
        return self._systools.parse_wdutil_scan(output)

    def parse_airport_scan(self, output: str) -> int:
        """Parse airport -s output. Returns number of networks found."""
        return self._systools.parse_airport_scan(output)

    def parse_macos_networks(self, output: str) -> None:
        """Parse system_profiler output to extract network information."""
        self._sp.parse_macos_networks(output)

    def extract_network_info(self, lines, start_index: int) -> Optional[NetworkInfo]:
        """Extract one network's details from system_profiler lines."""
        return self._sp.extract_network_info(lines, start_index)
