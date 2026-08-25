"""macOS Location Services permission handling.

Extracted from macos_scanner.py (Phase-2 split): permission discovery and the
CoreLocation request flow are isolated here so the scanner facade stays small.
"""

import sys
import time

from wifi_jammer.core.interfaces import ILogger
from wifi_jammer.utils.python_detector import find_python_with_permission


class MacOSPermissions:
    """Detects which Python has Location Services permission and requests it."""

    def __init__(self, logger: ILogger) -> None:
        self.logger = logger
        self.python_with_permission = None

    def check_permission(self) -> None:
        """Check which Python has Location Services permission and request if needed."""
        from wifi_jammer.utils.platform_utils import is_macos

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
            from CoreWLAN import CWWiFiClient  # type: ignore[import-not-found]

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

