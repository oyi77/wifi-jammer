"""macOS system-tool scanning and output parsing (wdutil/airport/system_profiler).

Extracted from macos_scanner.py (Phase-2 split). Pure string-parsing helpers are
covered by characterization fixtures in tests/test_macos_parsers.py.
"""

import os
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo
from wifi_jammer.scanner.scan_state import ScanState
from wifi_jammer.scanner.macos_sp_parsers import SystemProfilerParsers


class MacOSSystemTools:
    """wdutil/airport/system_profiler based discovery and parsing."""

    def __init__(
        self,
        logger: ILogger,
        state: ScanState,
        scapy_fallback: Callable[[str, Optional[int]], None],
    ) -> None:
        self.logger = logger
        self.state = state
        self._scapy_fallback = scapy_fallback
        self._sp = SystemProfilerParsers(logger=logger, state=state)

    def scan(self, interface: str, channel: Optional[int] = None) -> None:
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
                    networks_found = self.parse_wdutil_scan(result.stdout)
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
                            networks_found = self.parse_airport_scan(result.stdout)
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
            if not self.state.networks:
                try:
                    self.logger.info("Trying system_profiler as fallback...")
                    result = subprocess.run(
                        ["system_profiler", "SPAirPortDataType"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    if result.returncode == 0:
                        self._sp.parse_macos_networks(result.stdout)
                        if len(self.state.networks) > 0:
                            self.logger.info(
                                f"✅ system_profiler found {len(self.state.networks)} network(s)"
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
                    self._scapy_fallback(interface, channel)
                    if len(self.state.networks) > 0:
                        return
                except Exception as e:
                    self.logger.debug(f"Scapy scanning failed: {e}")
            else:
                # Show helpful message if no networks found and not running as root
                if not self.state.networks:
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

    def parse_wdutil_scan(self, output: str) -> int:
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

                # Look for SSID — \b prevents matching inside "BSSID : ..." lines
                # (substring "SSID" previously overwrote the SSID with the MAC)
                ssid_match = re.search(r"\bSSID\s*:\s*(.+)", line, re.IGNORECASE)
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

                # Flush only on the next network header (a "Name:" line without
                # a field separator) — flushing at the BSSID line previously
                # dropped channel/RSSI/security, which always trail it.
                is_header = line.endswith(":") and ":" not in line[:-1]
                if (
                    is_header
                    and current_network
                    and "ssid" in current_network
                    and "bssid" in current_network
                ):
                    networks_found += self._append_wdutil_network(current_network)
                    current_network = {}

            if "ssid" in current_network and "bssid" in current_network:
                networks_found += self._append_wdutil_network(current_network)
        except Exception as e:
            self.logger.debug(f"Error parsing wdutil scan: {e}")

        return networks_found


    def _append_wdutil_network(self, data: Dict[str, Any]) -> int:
        """Add one parsed wdutil network to state; returns 1 when newly added."""
        network_info = NetworkInfo(
            ssid=data.get("ssid", "Unknown"),
            bssid=data["bssid"],
            channel=data.get("channel", 0),
            rssi=data.get("rssi", -50),
            encryption=data.get("encryption", "Unknown"),
            clients=[],
        )
        with self.state.lock:
            if any(n.bssid == network_info.bssid for n in self.state.networks):
                return 0
            self.state.networks.append(network_info)
        self.logger.debug(
            f"wdutil found: {network_info.ssid} ({network_info.bssid})"
        )
        return 1


    def parse_airport_scan(self, output: str) -> int:
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

                    with self.state.lock:
                        if not any(n.bssid == bssid for n in self.state.networks):
                            self.state.networks.append(network_info)
                            networks_found += 1
                            self.logger.debug(
                                f"Airport found: {ssid} ({bssid}) on channel {channel}"
                            )
        except Exception as e:
            self.logger.error(f"Error parsing airport scan: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())

        return networks_found

