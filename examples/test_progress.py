#!/usr/bin/env python3
"""
Test script to demonstrate improved progress tracking and logging.
"""

import sys
import os
import time

# Add the parent directory to the path so we can import wifi_jammer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifi_jammer.core.interfaces import AttackType, AttackConfig
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger


def test_progress_tracking():
    """Test the progress tracking functionality."""
    print("🔧 Testing WiFi Jammer Progress Tracking")
    print("=" * 50)

    # Initialize components
    factory = AttackFactory()

    # Create a test configuration
    config = AttackConfig(
        attack_type=AttackType.BEACON_FLOOD,
        target_bssid="00:11:22:33:44:55",  # Test BSSID
        target_ssid="TestNetwork",
        interface="wlan0",  # Will be ignored in test
        channel=1,
        count=100,  # Send 100 packets
        delay=0.1,
        verbose=True,
    )

    # Create attack
    attack = factory.create_attack(config.attack_type)

    # Set up progress callback
    def progress_callback(stats):
        print(
            f"\r📊 Progress: {stats.packets_sent} packets, {stats.packets_per_second:.1f} pps, {stats.success_rate:.1f}% success",
            end="",
        )

    attack.set_progress_callback(progress_callback)

    # Test the attack (without actually sending packets)
    print("🚀 Starting test attack...")
    print("📋 Configuration:")
    print(f"   Attack Type: {config.attack_type.value}")
    print(f"   Target: {config.target_bssid}")
    print(f"   Packet Count: {config.count}")
    print(f"   Delay: {config.delay}s")
    print()

    # Simulate attack progress
    print("🔄 Simulating attack progress...")
    for i in range(10):
        # Simulate packet sending
        attack._stats.packets_sent += 10
        attack._stats.packets_failed += 1
        attack._stats.start_time = time.time() - 5  # Simulate 5 seconds elapsed

        # Call progress callback
        progress_callback(attack._stats)
        time.sleep(0.5)

    print("\n\n✅ Test completed!")
    print("📈 Final Stats:")
    print(f"   Packets Sent: {attack._stats.packets_sent:,}")
    print(f"   Packets Failed: {attack._stats.packets_failed:,}")
    print(f"   Success Rate: {attack._stats.success_rate:.1f}%")
    print(f"   Duration: {attack._stats.duration:.1f}s")
    print(f"   Packets/Second: {attack._stats.packets_per_second:.1f}")


def test_enhanced_logging():
    """Test the enhanced logging functionality."""
    print("\n🔧 Testing Enhanced Logging")
    print("=" * 50)

    logger = RichLogger()

    # Test different log levels
    logger.info("This is an info message")
    logger.success("This is a success message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.debug("This is a debug message")
    logger.status("This is a status message")

    # Test packet logging
    logger.packet_sent(1234, "00:11:22:33:44:55")

    # Test attack start/stop logging
    logger.attack_started("DeauthAttack", "00:11:22:33:44:55")

    stats = {
        "packets_sent": 1000,
        "packets_failed": 50,
        "duration": 30.5,
        "success_rate": 95.2,
    }
    logger.attack_stopped(stats)


if __name__ == "__main__":
    try:
        test_enhanced_logging()
        test_progress_tracking()
        print("\n🎉 All tests completed successfully!")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)
