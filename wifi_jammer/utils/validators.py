"""
Input validation utilities for WiFi jamming tool.
"""

import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from wifi_jammer.core.interfaces import AttackConfig


def is_valid_mac(mac: str) -> bool:
    """Check if a string is a valid MAC address.

    Args:
        mac: MAC address string to validate

    Returns:
        True if valid MAC address, False otherwise
    """
    if not mac or not isinstance(mac, str):
        return False
    return bool(re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac.strip()))


def is_valid_bssid(bssid: str) -> bool:
    """Check if a string is a valid BSSID (same as MAC for our purposes).

    Args:
        bssid: BSSID string to validate

    Returns:
        True if valid BSSID, False otherwise
    """
    return is_valid_mac(bssid)


def is_valid_interface_name(interface: str) -> bool:
    """Check if a string is a valid network interface name.

    Args:
        interface: Interface name to validate

    Returns:
        True if valid interface name, False otherwise
    """
    if not interface or not isinstance(interface, str):
        return False
    # Interface names are typically alphanumeric with underscores/dashes
    # Length should be reasonable (1-16 chars typically)
    interface = interface.strip()
    if not interface or len(interface) > 16:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", interface))


def is_valid_channel(channel: int, band: Optional[str] = None) -> bool:
    """Check if a channel number is valid.

    Args:
        channel: Channel number to validate
        band: Optional band ('2.4GHz' or '5GHz')

    Returns:
        True if valid channel, False otherwise
    """
    if not isinstance(channel, int):
        return False

    if band == "2.4GHz":
        return 1 <= channel <= 14
    elif band == "5GHz":
        return 36 <= channel <= 165
    else:
        # Accept both bands
        return (1 <= channel <= 14) or (36 <= channel <= 165)


def is_valid_packet_count(count: int) -> bool:
    """Check if packet count is valid.

    Args:
        count: Packet count to validate (0 means unlimited)

    Returns:
        True if valid count, False otherwise
    """
    if not isinstance(count, int):
        return False
    return count >= 0


def is_valid_delay(delay: float) -> bool:
    """Check if delay value is valid.

    Args:
        delay: Delay in seconds

    Returns:
        True if valid delay, False otherwise
    """
    if not isinstance(delay, (int, float)):
        return False
    return 0.0 <= delay <= 60.0


def is_valid_hop_interval(interval: float) -> bool:
    """Check if channel hopping interval is valid.

    Args:
        interval: Hopping interval in seconds

    Returns:
        True if valid interval, False otherwise
    """
    if not isinstance(interval, (int, float)):
        return False
    return 0.1 <= interval <= 10.0


def is_valid_capture_duration(duration: int) -> bool:
    """Check if capture duration is valid.

    Args:
        duration: Capture duration in seconds

    Returns:
        True if valid duration, False otherwise
    """
    if not isinstance(duration, int):
        return False
    return 1 <= duration <= 3600


def validate_attack_config(config: "AttackConfig") -> tuple[bool, Optional[str]]:
    """Validate attack configuration.

    Args:
        config: AttackConfig object to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not config:
        return False, "Configuration is None"

    # Validate target BSSID
    if config.target_bssid and not is_valid_bssid(config.target_bssid):
        return False, f"Invalid target BSSID: {config.target_bssid}"

    # Validate interface
    if config.interface and not is_valid_interface_name(config.interface):
        return False, f"Invalid interface name: {config.interface}"

    # Validate channel
    if config.channel and not is_valid_channel(config.channel):
        return False, f"Invalid channel: {config.channel}"

    # Validate packet count
    if not is_valid_packet_count(config.count):
        return False, f"Invalid packet count: {config.count}"

    # Validate delay
    if not is_valid_delay(config.delay):
        return False, f"Invalid delay: {config.delay}"

    # Validate source MAC if provided
    if config.source_mac and not is_valid_mac(config.source_mac):
        return False, f"Invalid source MAC: {config.source_mac}"

    return True, None
