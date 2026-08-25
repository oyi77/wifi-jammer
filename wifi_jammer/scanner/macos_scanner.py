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

from typing import Callable, Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo
from wifi_jammer.scanner.scan_state import ScanState
from wifi_jammer.scanner.macos_permissions import MacOSPermissions
from wifi_jammer.scanner.macos_corewlan import CoreWLANScanner
from wifi_jammer.scanner.macos_systools import MacOSSystemTools


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

    # -- Parsing (delegated, fixture-covered) ------------------------------

    def parse_wdutil_scan(self, output: str) -> int:
        """Parse wdutil scan output. Returns number of networks found."""
        return self._systools.parse_wdutil_scan(output)

    def parse_airport_scan(self, output: str) -> int:
        """Parse airport -s output. Returns number of networks found."""
        return self._systools.parse_airport_scan(output)

    def parse_macos_networks(self, output: str) -> None:
        """Parse system_profiler output to extract network information."""
        self._systools.parse_macos_networks(output)

    def extract_network_info(self, lines, start_index: int) -> Optional[NetworkInfo]:
        """Extract one network's details from system_profiler lines."""
        return self._systools.extract_network_info(lines, start_index)
