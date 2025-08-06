"""
Core interfaces for WiFi jamming functionality.
Following SOLID principles with clear separation of concerns.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Enumeration of available attack types."""
    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    BEACON_FLOOD = "beacon_flood"
    PROBE_RESPONSE = "probe_response"
    AUTH_FLOOD = "auth_flood"
    ASSOC_FLOOD = "assoc_flood"


@dataclass
class NetworkInfo:
    """Data class for network information."""
    ssid: str
    bssid: str
    channel: int
    rssi: int
    encryption: str
    clients: List[str] = None


@dataclass
class AttackConfig:
    """Configuration for attack parameters."""
    attack_type: AttackType
    target_bssid: str
    target_ssid: str = ""
    source_mac: str = ""
    interface: str = ""
    channel: int = 0
    count: int = 0
    delay: float = 0.1
    verbose: bool = False


class INetworkScanner(ABC):
    """Interface for network scanning functionality."""
    
    @abstractmethod
    def scan_networks(self, interface: str, channel: Optional[int] = None) -> List[NetworkInfo]:
        """Scan for available networks."""
        pass
    
    @abstractmethod
    def get_interface_list(self) -> List[str]:
        """Get list of available interfaces."""
        pass


class IAttackStrategy(ABC):
    """Interface for attack strategies."""
    
    @abstractmethod
    def execute(self, config: AttackConfig) -> bool:
        """Execute the attack strategy."""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the attack."""
        pass
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if attack is running."""
        pass


class IMonitor(ABC):
    """Interface for monitoring functionality."""
    
    @abstractmethod
    def start_monitoring(self, interface: str, callback: callable) -> None:
        """Start monitoring network traffic."""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        pass


class ILogger(ABC):
    """Interface for logging functionality."""
    
    @abstractmethod
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message."""
        pass
    
    @abstractmethod
    def error(self, message: str) -> None:
        """Log an error message."""
        pass
    
    @abstractmethod
    def warning(self, message: str) -> None:
        """Log a warning message."""
        pass


class IConfigManager(ABC):
    """Interface for configuration management."""
    
    @abstractmethod
    def load_config(self, file_path: str) -> Dict[str, Any]:
        """Load configuration from file."""
        pass
    
    @abstractmethod
    def save_config(self, config: Dict[str, Any], file_path: str) -> None:
        """Save configuration to file."""
        pass


class IAttackFactory(ABC):
    """Factory interface for creating attack strategies."""
    
    @abstractmethod
    def create_attack(self, attack_type: AttackType) -> IAttackStrategy:
        """Create an attack strategy instance."""
        pass 