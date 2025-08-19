"""
Configuration management for WiFi Jammer Tool.
"""

import os
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ToolConfig:
    """Configuration for the WiFi Jammer Tool."""
    
    # Attack settings
    default_packet_count: int = 0  # 0 = unlimited
    default_delay: float = 0.1
    default_verbose: bool = False
    
    # Network settings
    scan_timeout: int = 10
    max_networks: int = 100
    
    # Interface settings
    auto_monitor_mode: bool = True
    auto_channel_set: bool = True
    
    # Logging settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    log_to_console: bool = True
    
    # Security settings
    require_confirmation: bool = True
    max_packets_per_second: int = 1000
    rate_limit_enabled: bool = True
    
    # UI settings
    progress_update_interval: float = 2.0
    show_detailed_stats: bool = True
    color_output: bool = True


class ConfigManager:
    """Manages configuration for the WiFi Jammer Tool."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager."""
        if config_file is None:
            config_file = self._get_default_config_path()
        
        self.config_file = config_file
        self.config = self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        config_dir = Path.home() / ".wifi_jammer"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.yaml")
    
    def _load_config(self) -> ToolConfig:
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                    if config_data:
                        return ToolConfig(**config_data)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
        
        # Return default configuration
        return ToolConfig()
    
    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            config_dir = os.path.dirname(self.config_file)
            os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                yaml.dump(asdict(self.config), f, default_flow_style=False)
            
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value."""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            return True
        return False
    
    def update(self, updates: Dict[str, Any]) -> None:
        """Update multiple configuration values."""
        for key, value in updates.items():
            self.set(key, value)
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        self.config = ToolConfig()
    
    def get_attack_config(self) -> Dict[str, Any]:
        """Get attack-related configuration."""
        return {
            'default_packet_count': self.config.default_packet_count,
            'default_delay': self.config.default_delay,
            'default_verbose': self.config.default_verbose,
            'max_packets_per_second': self.config.max_packets_per_second,
            'rate_limit_enabled': self.config.rate_limit_enabled
        }
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network-related configuration."""
        return {
            'scan_timeout': self.config.scan_timeout,
            'max_networks': self.config.max_networks,
            'auto_monitor_mode': self.config.auto_monitor_mode,
            'auto_channel_set': self.config.auto_channel_set
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging-related configuration."""
        return {
            'log_level': self.config.log_level,
            'log_file': self.config.log_file,
            'log_to_console': self.config.log_to_console
        }


# Global configuration instance
config_manager = ConfigManager()


def get_config() -> ToolConfig:
    """Get global configuration."""
    return config_manager.config


def get_config_value(key: str, default: Any = None) -> Any:
    """Get configuration value."""
    return config_manager.get(key, default)


def set_config_value(key: str, value: Any) -> bool:
    """Set configuration value."""
    return config_manager.set(key, value)


def save_config() -> bool:
    """Save configuration."""
    return config_manager.save_config()
