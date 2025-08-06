"""
Base attack class for WiFi jamming attacks.
"""

import threading
import time
from abc import ABC, abstractmethod
from typing import Optional
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoReq
from ..core.interfaces import IAttackStrategy, AttackConfig
from ..utils.logger import RichLogger


class BaseAttack(IAttackStrategy, ABC):
    """Base class for all attack strategies."""
    
    def __init__(self, logger: Optional[RichLogger] = None):
        self.logger = logger or RichLogger()
        self._running = False
        self._thread = None
        self._config = None
    
    def execute(self, config: AttackConfig) -> bool:
        """Execute the attack with given configuration."""
        if self._running:
            self.logger.warning("Attack already running")
            return False
        
        self._config = config
        self._running = True
        
        try:
            # Set interface to monitor mode
            self._set_monitor_mode(config.interface)
            
            # Set channel if specified
            if config.channel > 0:
                self._set_channel(config.interface, config.channel)
            
            # Start attack in background thread
            self._thread = threading.Thread(target=self._attack_loop)
            self._thread.daemon = True
            self._thread.start()
            
            self.logger.success(f"Started {self.__class__.__name__} attack")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start attack: {e}")
            self._running = False
            return False
    
    def stop(self) -> None:
        """Stop the attack."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self.logger.info("Attack stopped")
    
    def is_running(self) -> bool:
        """Check if attack is running."""
        return self._running
    
    @abstractmethod
    def _create_packet(self) -> Packet:
        """Create the attack packet. Must be implemented by subclasses."""
        pass
    
    def _attack_loop(self):
        """Main attack loop."""
        packet_count = 0
        
        while self._running:
            try:
                packet = self._create_packet()
                
                if packet:
                    sendp(packet, iface=self._config.interface, verbose=False)
                    packet_count += 1
                    
                    if self._config.verbose:
                        self.logger.log(f"Sent packet #{packet_count}")
                    
                    # Check if we've reached the count limit
                    if self._config.count > 0 and packet_count >= self._config.count:
                        self.logger.info(f"Reached packet limit ({self._config.count})")
                        break
                
                # Delay between packets
                time.sleep(self._config.delay)
                
            except Exception as e:
                self.logger.error(f"Error in attack loop: {e}")
                time.sleep(1)
        
        self._running = False
    
    def _set_monitor_mode(self, interface: str):
        """Set interface to monitor mode."""
        try:
            import platform
            if platform.system() == "Windows":
                self.logger.warning("Monitor mode not supported on Windows")
                return
                
            if "mon" not in interface and "monitor" not in interface:
                os.system(f"sudo iwconfig {interface} mode monitor")
                time.sleep(1)
        except Exception as e:
            self.logger.error(f"Error setting monitor mode: {e}")
    
    def _set_channel(self, interface: str, channel: int):
        """Set interface channel."""
        try:
            import platform
            if platform.system() == "Windows":
                self.logger.warning("Channel setting not supported on Windows")
                return
                
            os.system(f"sudo iwconfig {interface} channel {channel}")
            time.sleep(0.1)
        except Exception as e:
            self.logger.error(f"Error setting channel: {e}")
    
    def _get_random_mac(self) -> str:
        """Generate a random MAC address."""
        return f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
    
    def _get_source_mac(self) -> str:
        """Get source MAC address."""
        if self._config.source_mac:
            return self._config.source_mac
        return self._get_random_mac() 