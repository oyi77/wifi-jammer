"""Locate the currently associated macOS network via system CLI tools.

Carried over verbatim from the post-CoreWLAN half of the original
``MacOSScanner.get_current_network`` during the Phase-2 split: airport -I,
system_profiler, networksetup and wdutil parsing chained with airport -s
matching. Pure discovery — no shared mutable state.
"""

import os
import re
import subprocess
import time

from typing import Optional

from wifi_jammer.core.interfaces import ILogger, NetworkInfo


def find_current_network(
    logger: ILogger, interface: str
) -> Optional[NetworkInfo]:
        """Locate the currently associated network via CLI tools.

        Carried over verbatim from the post-CoreWLAN half of the original
        ``MacOSScanner.get_current_network`` (Phase-2 split).
        """
        try:
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
                    logger.warning(
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
            logger.debug(f"Could not get current network info: {e}")

        return None
