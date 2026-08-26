"""system_profiler SPAirPortDataType output parsing.

Split from macos_systools.py so every module stays well under the
project's module-size target. Fixture-covered by
tests/test_macos_parsers.py (TestSystemProfilerParser).
"""

import re
from typing import Any, Dict, List, Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo
from wifi_jammer.scanner.scan_state import ScanState


class SystemProfilerParsers:
    """Parses system_profiler current-network and other-networks sections."""

    def __init__(self, logger: ILogger, state: ScanState) -> None:
        self.logger = logger
        self.state = state

    def parse_macos_networks(self, output: str) -> None:
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
                            with self.state.lock:
                                if not any(
                                    n.bssid == network_info.bssid
                                    for n in self.state.networks
                                ):
                                    self.state.networks.append(network_info)
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
                            parsed_network = self.extract_network_info(lines, i)
                            if parsed_network:
                                with self.state.lock:
                                    if not any(
                                        n.ssid == network_name
                                        for n in self.state.networks
                                    ):
                                        self.state.networks.append(parsed_network)

                # Stop parsing if we hit another major section
                elif in_networks_section and line.startswith("awdl0:"):
                    break

        except Exception as e:
            self.logger.error(f"Error parsing macOS networks: {e}")

    def extract_network_info(
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

