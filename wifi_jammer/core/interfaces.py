"""
Core interfaces for WiFi jamming functionality.
Following SOLID principles with clear separation of concerns.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Callable, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

if TYPE_CHECKING:
    from wifi_jammer.attacks.base_attack import AttackStats


class AttackType(Enum):
    """Enumeration of available attack types."""

    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    BEACON_FLOOD = "beacon_flood"
    PROBE_RESPONSE = "probe_response"
    AUTH_FLOOD = "auth_flood"
    ASSOC_FLOOD = "assoc_flood"
    CHANNEL_HOP = "channel_hop"
    PMKID_CAPTURE = "pmkid_capture"
    EVIL_TWIN = "evil_twin"
    NETCUT = "netcut"


@dataclass
class NetworkInfo:
    """Data class for network information."""

    ssid: str
    bssid: str
    channel: int
    rssi: int
    encryption: str
    clients: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Initialize clients list if None."""
        if self.clients is None:
            self.clients = []


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
    target_client: str = ""
    verbose: bool = False
    hop_interval: float = 0.5
    hop_channels: Optional[List[int]] = None
    capture_file: str = ""
    capture_duration: int = 60
    spoof_ssid: str = ""
    target_clients: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.hop_channels is None:
            self.hop_channels = []
        if self.target_clients is None:
            self.target_clients = []


class INetworkScanner(ABC):
    """Interface for network scanning functionality."""

    @abstractmethod
    def scan_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> List[NetworkInfo]:
        """Scan for available networks."""
        ...

    @abstractmethod
    def get_interface_list(self) -> List[str]:
        """Get list of available interfaces."""
        ...

    @abstractmethod
    def scan_clients(
        self,
        interface: str,
        ap_bssid: str,
        channel: Optional[int] = None,
        duration: int = 30,
    ) -> Dict[str, float]:
        """Scan for clients connected to a specific access point.

        Args:
            interface: Network interface to use
            ap_bssid: BSSID of the access point
            channel: Channel to scan on (optional)
            duration: Duration of scan in seconds

        Returns:
            Dictionary mapping client MAC addresses to last seen timestamps
        """
        ...


class IAttackStrategy(ABC):
    """Interface for attack strategies."""

    @abstractmethod
    def execute(self, config: AttackConfig) -> bool:
        """Execute the attack strategy."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop the attack."""
        ...

    @abstractmethod
    def is_running(self) -> bool:
        """Check if attack is running."""
        ...

    @abstractmethod
    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the attack to complete."""
        ...

    @abstractmethod
    def get_stats(self) -> "AttackStats":
        """Get current attack statistics."""
        ...

    @abstractmethod
    def set_progress_callback(self, callback: Callable[["AttackStats"], None]) -> None:
        """Set progress callback function."""
        ...


class ILogger(ABC):
    """Interface for logging functionality."""

    @abstractmethod
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message."""
        ...

    @abstractmethod
    def info(self, message: str) -> None:
        """Log an info message."""
        ...

    @abstractmethod
    def debug(self, message: str) -> None:
        """Log a debug message."""
        ...

    @abstractmethod
    def error(self, message: str) -> None:
        """Log an error message."""
        ...

    @abstractmethod
    def warning(self, message: str) -> None:
        """Log a warning message."""
        ...

    @abstractmethod
    def success(self, message: str) -> None:
        """Log a success message."""
        ...

    @abstractmethod
    def status(self, message: str) -> None:
        """Log a status message."""
        ...


class IConfigManager(ABC):
    """Interface for configuration management."""

    @abstractmethod
    def load_config(self, file_path: str) -> Dict[str, Any]:
        """Load configuration from file."""
        ...

    @abstractmethod
    def save_config(self, config: Dict[str, Any], file_path: str) -> None:
        """Save configuration to file."""
        ...


class IAttackFactory(ABC):
    """Factory interface for creating attack strategies."""

    @abstractmethod
    def create_attack(self, attack_type: AttackType) -> "IAttackStrategy":
        """Create an attack strategy instance."""
        ...

    @abstractmethod
    def get_available_attacks(self) -> List[AttackType]:
        """Get list of available attack types."""
        ...
