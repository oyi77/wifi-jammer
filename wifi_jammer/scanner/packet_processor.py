"""802.11 packet processing for the network scanner.

Extracts network information from captured beacon, probe response, and
data frames, mutating the shared :class:`ScanState` under its lock.

Decoupled from the capture layer (scapy ``sniff``) so the parsing logic
is independently testable.
"""

from typing import Any, List

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp

from wifi_jammer.core.interfaces import NetworkInfo, ILogger
from wifi_jammer.scanner.scan_state import ScanState


class PacketProcessor:
    """Processes 802.11 packets and updates the shared scan state."""

    def __init__(self, logger: ILogger, state: ScanState) -> None:
        self.logger = logger
        self.state = state

    def handle(self, pkt: Any) -> None:
        """Dispatch a captured packet to the matching processor."""
        try:
            if pkt.haslayer(Dot11Beacon):
                self.process_beacon(pkt)
            elif pkt.haslayer(Dot11ProbeResp):
                self.process_probe_response(pkt)
            elif pkt.haslayer(Dot11) and pkt.type == 2:
                # Also process data frames (type=2) to detect clients
                self.process_data(pkt)
        except (AttributeError, KeyError, TypeError, ValueError):
            # Silently ignore packet processing errors
            pass

    def process_beacon(self, pkt: Any) -> None:
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

                    with self.state.lock:
                        # Update existing network or add new one
                        existing = next(
                            (n for n in self.state.networks if n.bssid == bssid), None
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
                            self.state.networks.append(network_info)

        except Exception as e:
            self.logger.error(f"Error processing beacon packet: {e}")

    def process_probe_response(self, pkt: Any) -> None:
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
                    with self.state.lock:
                        existing = next(
                            (n for n in self.state.networks if n.bssid == bssid), None
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
                            self.state.networks.append(network_info)

        except Exception as e:
            self.logger.error(f"Error processing probe response: {e}")

    def process_data(self, pkt: Any) -> None:
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
                with self.state.lock:
                    network = next(
                        (n for n in self.state.networks if n.bssid == bssid), None
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
