"""
Base attack class for WiFi jamming attacks.
"""

import threading
import time
import os
import random
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoReq
from ..core.interfaces import IAttackStrategy, AttackConfig
from ..utils.logger import RichLogger


@dataclass
class AttackStats:
    """Statistics for attack progress."""
    packets_sent: int = 0
    packets_failed: int = 0
    start_time: Optional[float] = None
    last_packet_time: Optional[float] = None
    errors: list = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    @property
    def duration(self) -> float:
        """Get attack duration in seconds."""
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time
    
    @property
    def packets_per_second(self) -> float:
        """Get packets per second rate."""
        if self.duration == 0:
            return 0.0
        return self.packets_sent / self.duration
    
    @property
    def success_rate(self) -> float:
        """Get success rate percentage."""
        total = self.packets_sent + self.packets_failed
        if total == 0:
            return 0.0
        return (self.packets_sent / total) * 100


class BaseAttack(IAttackStrategy, ABC):
    """Base class for all attack strategies."""
    
    def __init__(self, logger: Optional[RichLogger] = None):
        self.logger = logger or RichLogger()
        self._running = False
        self._thread = None
        self._config = None
        self._stats = AttackStats()
        self._progress_callback = None
    
    @abstractmethod
    def _create_packet(self) -> Optional[Packet]:
        """Create the attack packet. Must be implemented by subclasses."""
        pass
    
    def execute(self, config: AttackConfig) -> bool:
        """Execute the attack with given configuration."""
        if self._running:
            self.logger.warning("Attack already running")
            return False
        
        self._config = config
        self._running = True
        self._stats = AttackStats()
        self._stats.start_time = time.time()
        
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
            
            # Log attack start with enhanced formatting
            attack_type = self.__class__.__name__
            target = config.target_bssid or "Broadcast"
            self.logger.attack_started(attack_type, target)
            
            self.logger.info(f"Interface: {config.interface}")
            self.logger.info(f"Channel: {config.channel}")
            self.logger.info(f"Packet count: {'Unlimited' if config.count == 0 else config.count}")
            self.logger.info(f"Delay: {config.delay}s")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start attack: {e}")
            self._running = False
            return False
    
    def stop(self) -> None:
        """Stop the attack."""
        if not self._running:
            return
        
        self._running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        
        self._log_final_stats()
    
    def is_running(self) -> bool:
        """Check if attack is running."""
        return self._running
    
    def get_stats(self) -> AttackStats:
        """Get current attack statistics."""
        return self._stats.copy() if hasattr(self._stats, 'copy') else self._stats
    
    def set_progress_callback(self, callback: callable) -> None:
        """Set progress callback function."""
        self._progress_callback = callback
    
    def _attack_loop(self):
        """Main attack loop."""
        packet_count = 0
        last_progress_time = time.time()
        progress_interval = 5.0  # Log progress every 5 seconds
        
        while self._running:
            try:
                # Create and send packet
                packet = self._create_packet()
                
                if packet:
                    # Send packet
                    sendp(packet, iface=self._config.interface, verbose=False)
                    
                    self._stats.packets_sent += 1
                    self._stats.last_packet_time = time.time()
                    packet_count += 1
                    
                    # Call progress callback if set
                    if self._progress_callback:
                        try:
                            self._progress_callback(self._stats)
                        except Exception as e:
                            self.logger.error(f"Progress callback error: {e}")
                    
                    # Log progress periodically
                    current_time = time.time()
                    if current_time - last_progress_time >= progress_interval:
                        self._log_progress()
                        last_progress_time = current_time
                    
                    # Check if we've reached the count limit
                    if self._config.count > 0 and packet_count >= self._config.count:
                        self.logger.info(f"Reached packet limit ({self._config.count})")
                        break
                else:
                    self.logger.warning("Failed to create packet")
                    self._stats.packets_failed += 1
                
                # Delay between packets
                time.sleep(self._config.delay)
                
            except Exception as e:
                error_msg = f"Error in attack loop: {e}"
                self.logger.error(error_msg)
                self._stats.packets_failed += 1
                self._stats.errors.append(error_msg)
                time.sleep(1)
        
        self._running = False
    
    def _log_progress(self):
        """Log current attack progress."""
        stats = self._stats
        duration = stats.duration
        
        if duration > 0:
            pps = stats.packets_per_second
            success_rate = stats.success_rate
            
            self.logger.status(
                f"Progress: {stats.packets_sent:,} packets sent, "
                f"{pps:.1f} pps, {success_rate:.1f}% success rate, "
                f"{duration:.1f}s elapsed"
            )
    
    def _log_final_stats(self):
        """Log final attack statistics."""
        stats = self._stats
        duration = stats.duration
        
        if duration > 0:
            pps = stats.packets_per_second
            success_rate = stats.success_rate
            
            self.logger.success(
                f"Attack completed: {stats.packets_sent:,} packets sent, "
                f"{stats.packets_failed:,} failed, {pps:.1f} pps average, "
                f"{success_rate:.1f}% success rate, {duration:.1f}s total"
            )
            
            if stats.errors:
                self.logger.warning(f"Encountered {len(stats.errors)} errors during attack")
    
    def _set_monitor_mode(self, interface: str):
        """Set interface to monitor mode."""
        try:
            import platform
            if platform.system() == "Windows":
                self.logger.warning("Monitor mode not supported on Windows")
                return
                
            if "mon" not in interface and "monitor" not in interface:
                self.logger.status(f"Setting {interface} to monitor mode...")
                os.system(f"sudo iwconfig {interface} mode monitor")
                time.sleep(1)
                self.logger.success(f"Interface {interface} set to monitor mode")
        except Exception as e:
            self.logger.error(f"Error setting monitor mode: {e}")
    
    def _set_channel(self, interface: str, channel: int):
        """Set interface channel."""
        try:
            import platform
            if platform.system() == "Windows":
                self.logger.warning("Channel setting not supported on Windows")
                return
                
            self.logger.status(f"Setting {interface} to channel {channel}...")
            os.system(f"sudo iwconfig {interface} channel {channel}")
            time.sleep(0.1)
            self.logger.success(f"Interface {interface} set to channel {channel}")
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