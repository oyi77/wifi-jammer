#!/usr/bin/env python3
"""
Characterization fixtures for the macOS system-tool parsers (wdutil, airport,
system_profiler). Pure string parsing — runs on any OS. Pins current behavior
across the Phase-2 module split of macos_scanner.py.
"""

import unittest
import threading
from unittest.mock import Mock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifi_jammer.scanner.macos_scanner import MacOSScanner
from wifi_jammer.utils.logger import RichLogger

WDUTIL_SCAN_OUTPUT = """\
scanTime: 2026-08-25 10:00:00.000
Wi-Fi:
  ScanTimestamp: 2026-08-25
  Networks:
    KOST BERLIAN:
      SSID : KOST BERLIAN
      BSSID : 10:8f:fe:00:a3:e0
      RSSI : -55 dBm
      Channel : 149 (5GHz, 80MHz)
      Security : WPA2 Personal
    HomeNet_2G:
      SSID : HomeNet_2G
      BSSID : a4:2b:8c:11:22:33
      RSSI : -61 dBm
      Channel : 6 (2GHz, 20MHz)
      Security : WPA Personal
"""

AIRPORT_SCAN_OUTPUT = """\
WARNING: The airport command line tool is deprecated and will be removed.
                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                     KOST BERLIAN 10:8f:fe:00:a3:e0 -77  149,-1  Y  -- WPA2(PSK/AES/AES)
                       HomeNet_2G a4:2b:8c:11:22:33 -60  6,-1    Y  -- WPA(PSK/AES,TKIP/TKIP)
                          OpenCafe 0a:1b:2c:3d:4e:5f -80  11,-1   Y  EU NONE
"""

SYSTEM_PROFILER_OUTPUT = """\
Wi-Fi:

    Software Versions:
      Menu Extra: 12.0
      IO80211Family: 1200

    Current Network Information:
      HomeNet_2G:
        PHY Mode: 802.11n
        Channel: 6 (2GHz, 20MHz)
        Country Code: ID
        Network Type: Infrastructure
        Security: WPA2 Personal
        Signal / Noise: -58 dBm / -92 dBm
        Transmit Rate: 72

    Other Local Wi-Fi Networks:
      KOST BERLIAN:
        PHY Mode: 802.11ac
        Channel: 149 (5GHz, 80MHz)
        Security: WPA2 Personal
        Signal / Noise: -77 dBm / -95 dBm
"""


def _make_scanner():
    logger = Mock(spec=RichLogger)
    return MacOSScanner(
        logger=logger,
        state=Mock(networks=[], lock=threading.Lock(), privacy_blocked_count=0),
        corewlan_available=lambda: False,
        install_corewlan=lambda: None,
        scapy_fallback=lambda interface, channel: None,
    )


class TestWdutilScanParser(unittest.TestCase):
    """parse_wdutil_scan behavior pinned against a realistic sample."""

    def setUp(self):
        self.scanner = _make_scanner()

    def test_parses_multiple_networks_with_details(self):
        found = self.scanner.parse_wdutil_scan(WDUTIL_SCAN_OUTPUT)
        self.assertEqual(found, 2)
        by_bssid = {n.bssid: n for n in self.scanner.state.networks}
        kost = by_bssid["10:8f:fe:00:a3:e0"]
        self.assertEqual(kost.ssid, "KOST BERLIAN")
        self.assertEqual(kost.channel, 149)
        self.assertEqual(kost.rssi, -55)
        home = by_bssid["a4:2b:8c:11:22:33"]
        self.assertEqual(home.channel, 6)
        self.assertEqual(home.encryption, "WPA")

    def test_no_networks_on_empty_output(self):
        self.assertEqual(self.scanner.parse_wdutil_scan(""), 0)


class TestAirportScanParser(unittest.TestCase):
    """parse_airport_scan behavior pinned against a realistic sample."""

    def setUp(self):
        self.scanner = _make_scanner()

    def test_parses_networks_skipping_warning_and_header(self):
        found = self.scanner.parse_airport_scan(AIRPORT_SCAN_OUTPUT)
        self.assertEqual(found, 3)
        by_bssid = {n.bssid: n for n in self.scanner.state.networks}
        self.assertIn("10:8f:fe:00:a3:e0", by_bssid)
        open_cafe = by_bssid["0a:1b:2c:3d:4e:5f"]
        self.assertEqual(open_cafe.encryption, "Open")
        self.assertEqual(open_cafe.channel, 11)
        kost = by_bssid["10:8f:fe:00:a3:e0"]
        self.assertEqual(kost.encryption, "WPA2")
        self.assertEqual(kost.rssi, -77)

    def test_deduplicates_by_bssid_across_calls(self):
        self.scanner.parse_airport_scan(AIRPORT_SCAN_OUTPUT)
        # Re-parsing must not duplicate entries already in state
        found_again = self.scanner.parse_airport_scan(AIRPORT_SCAN_OUTPUT)
        self.assertEqual(found_again, 0)
        self.assertEqual(len(self.scanner.state.networks), 3)


class TestSystemProfilerParser(unittest.TestCase):
    """parse_macos_networks / extract_network_info behavior pinned."""

    def setUp(self):
        self.scanner = _make_scanner()

    def test_other_local_section_yields_network(self):
        self.scanner.parse_macos_networks(SYSTEM_PROFILER_OUTPUT)
        ssids = [n.ssid for n in self.scanner.state.networks]
        self.assertIn("KOST BERLIAN", ssids)
        kost = next(n for n in self.scanner.state.networks if n.ssid == "KOST BERLIAN")
        self.assertEqual(kost.channel, 149)
        self.assertEqual(kost.encryption, "WPA2")
        self.assertEqual(kost.rssi, -77)

    def test_extract_network_info_reads_following_lines(self):
        lines = SYSTEM_PROFILER_OUTPUT.split("\n")
        start = next(
            i for i, ln in enumerate(lines) if ln.strip() == "KOST BERLIAN:"
        )
        info = self.scanner.extract_network_info(lines, start)
        self.assertIsNotNone(info)
        self.assertEqual(info.ssid, "KOST BERLIAN")  # type: ignore[union-attr]
        self.assertEqual(info.channel, 149)  # type: ignore[union-attr]
        self.assertEqual(info.encryption, "WPA2")  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
