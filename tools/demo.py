#!/usr/bin/env python3
"""
WiFi Jammer Tool - Comprehensive Demo
Demonstrates all features of the tool.
"""

import sys
import os
import time

# Add the project root to the Python path (go up from tools/ to project root)
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from wifi_jammer.core.interfaces import AttackType, AttackConfig  # noqa: E402
from wifi_jammer.scanner import ScapyNetworkScanner  # noqa: E402
from wifi_jammer.factory import AttackFactory  # noqa: E402
from wifi_jammer.utils import RichLogger  # noqa: E402
from wifi_jammer.config import get_config, set_config_value  # noqa: E402


class WiFiJammerDemo:
    """Comprehensive demo of WiFi Jammer Tool features."""

    def __init__(self):
        """Initialize the demo."""
        self.logger = RichLogger()
        self.scanner = ScapyNetworkScanner(self.logger)
        self.factory = AttackFactory()
        self.config = get_config()

        # Demo configuration
        self.demo_duration = 5  # seconds per attack
        self.demo_packet_count = 50

        self.logger.info("🚀 WiFi Jammer Tool Demo Initialized")

    def show_banner(self):
        """Display demo banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    WiFi Jammer Tool                          ║
║                        DEMO MODE                             ║
║                    By Paijo - v1.0.0                        ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.logger.info(banner)

    def demo_interface_detection(self):
        """Demonstrate interface detection."""
        self.logger.info("🔍 Demo: Interface Detection")
        self.logger.info("=" * 50)

        try:
            interfaces = self.scanner.get_interface_list()

            if interfaces:
                self.logger.success(f"Found {len(interfaces)} wireless interfaces:")
                for i, iface in enumerate(interfaces, 1):
                    self.logger.info(f"  {i}. {iface}")
            else:
                self.logger.warning("No wireless interfaces found")
                self.logger.info("This is normal in demo mode without actual hardware")

        except (OSError, RuntimeError, AttributeError) as e:
            self.logger.error(f"Interface detection error: {e}")

        self.logger.info("")

    def demo_network_scanning(self):
        """Demonstrate network scanning."""
        self.logger.info("📡 Demo: Network Scanning")
        self.logger.info("=" * 50)

        try:
            # Simulate network scanning
            self.logger.info("Scanning for networks...")
            time.sleep(1)  # Simulate scan time

            # Create mock networks for demo
            mock_networks = [
                ("DemoNetwork1", "00:11:22:33:44:55", 6, -45, "WPA2"),
                ("DemoNetwork2", "00:11:22:33:44:66", 11, -52, "WPA"),
                ("HiddenNetwork", "00:11:22:33:44:77", 1, -60, "WPA2"),
                ("OpenNetwork", "00:11:22:33:44:88", 6, -70, "Open"),
            ]

            self.logger.success(f"Found {len(mock_networks)} networks:")
            for i, (ssid, bssid, channel, rssi, encryption) in enumerate(
                mock_networks, 1
            ):
                self.logger.info(
                    f"  {i}. {ssid} ({bssid}) - Ch{channel}, {rssi}dBm, {encryption}"
                )

        except (OSError, RuntimeError, ValueError) as e:
            self.logger.error(f"Network scanning error: {e}")

        self.logger.info("")

    def demo_attack_types(self):
        """Demonstrate different attack types."""
        self.logger.info("⚔️  Demo: Attack Types")
        self.logger.info("=" * 50)

        attack_types = [
            (
                AttackType.DEAUTH,
                "Deauthentication Attack",
                "Disconnects clients from AP",
            ),
            (
                AttackType.DISASSOC,
                "Disassociation Attack",
                "Removes client associations",
            ),
            (AttackType.BEACON_FLOOD, "Beacon Flood Attack", "Creates fake networks"),
            (
                AttackType.AUTH_FLOOD,
                "Authentication Flood",
                "Overwhelms AP with auth requests",
            ),
            (
                AttackType.ASSOC_FLOOD,
                "Association Flood",
                "Overwhelms AP with association requests",
            ),
            (
                AttackType.PROBE_RESPONSE,
                "Probe Response Flood",
                "Responds to probe requests",
            ),
        ]

        for attack_type, name, description in attack_types:
            self.logger.info(f"🔸 {name}")
            self.logger.info(f"   Type: {attack_type.value}")
            self.logger.info(f"   Description: {description}")
            self.logger.info("")

    def demo_attack_execution(self):
        """Demonstrate attack execution."""
        self.logger.info("🚀 Demo: Attack Execution")
        self.logger.info("=" * 50)

        try:
            # Create demo attack configuration
            config = AttackConfig(
                attack_type=AttackType.BEACON_FLOOD,
                target_bssid="00:11:22:33:44:55",
                target_ssid="DemoTarget",
                interface="demo0",
                channel=6,
                count=self.demo_packet_count,
                delay=0.1,
                verbose=True,
            )

            self.logger.info("Configuration:")
            self.logger.info(f"  Attack Type: {config.attack_type.value}")
            self.logger.info(f"  Target: {config.target_bssid}")
            self.logger.info(f"  Interface: {config.interface}")
            self.logger.info(f"  Channel: {config.channel}")
            self.logger.info(f"  Packet Count: {config.count}")
            self.logger.info(f"  Delay: {config.delay}s")
            self.logger.info("")

            # Create attack instance
            attack = self.factory.create_attack(config.attack_type)

            self.logger.info("Creating attack instance...")
            self.logger.success(f"Attack class: {attack.__class__.__name__}")

            # Set up progress callback
            def progress_callback(stats):
                if stats.packets_sent % 10 == 0:  # Update every 10 packets
                    self.logger.status(
                        f"Progress: {stats.packets_sent}/{config.count} packets"
                    )

            attack.set_progress_callback(progress_callback)

            self.logger.info("")
            self.logger.info("Note: This is a demo - no actual packets will be sent")
            self.logger.info(
                "In real usage, the attack would execute with the above configuration"
            )

        except (OSError, RuntimeError, ValueError, AttributeError) as e:
            self.logger.error(f"Attack execution demo error: {e}")

        self.logger.info("")

    def demo_configuration(self):
        """Demonstrate configuration management."""
        self.logger.info("⚙️  Demo: Configuration Management")
        self.logger.info("=" * 50)

        try:
            # Show current configuration
            self.logger.info("Current Configuration:")
            self.logger.info(
                f"  Default Packet Count: {self.config.default_packet_count}"
            )
            self.logger.info(f"  Default Delay: {self.config.default_delay}s")
            self.logger.info(f"  Default Verbose: {self.config.default_verbose}")
            self.logger.info(f"  Scan Timeout: {self.config.scan_timeout}s")
            self.logger.info(f"  Max Networks: {self.config.max_networks}")
            self.logger.info(f"  Auto Monitor Mode: {self.config.auto_monitor_mode}")
            self.logger.info(f"  Rate Limit Enabled: {self.config.rate_limit_enabled}")
            self.logger.info(
                f"  Max Packets/Second: {self.config.max_packets_per_second}"
            )

            # Demonstrate configuration changes
            self.logger.info("")
            self.logger.info("Demonstrating configuration changes...")

            old_delay = self.config.default_delay
            new_delay = 0.2

            set_config_value("default_delay", new_delay)
            self.logger.success(
                f"Changed default delay from {old_delay}s to {new_delay}s"
            )

            # Reset for demo
            set_config_value("default_delay", old_delay)
            self.logger.info(f"Reset default delay to {old_delay}s")

        except (OSError, ValueError, AttributeError) as e:
            self.logger.error(f"Configuration demo error: {e}")

        self.logger.info("")

    def demo_security_features(self):
        """Demonstrate security features."""
        self.logger.info("🔒 Demo: Security Features")
        self.logger.info("=" * 50)

        security_features = [
            "Rate limiting to prevent network overload",
            "Configurable packet limits",
            "User confirmation requirements",
            "Comprehensive logging and audit trails",
            "Interface validation and safety checks",
            "Platform-specific capability detection",
            "Warning systems and legal disclaimers",
        ]

        for feature in security_features:
            self.logger.info(f"  ✓ {feature}")

        self.logger.info("")
        self.logger.warning("⚠️  IMPORTANT: This tool is for educational purposes only!")
        self.logger.warning(
            "   Use only on networks you own or have permission to test!"
        )
        self.logger.info("")

    def demo_architecture(self):
        """Demonstrate the tool's architecture."""
        self.logger.info("🏗️  Demo: Tool Architecture")
        self.logger.info("=" * 50)

        architecture_info = [
            ("Core Interfaces", "Clean abstractions following SOLID principles"),
            ("Platform Abstraction", "Cross-platform support (Linux, macOS, Windows)"),
            ("Attack Strategies", "Extensible attack framework with factory pattern"),
            ("Network Scanner", "Intelligent network discovery and analysis"),
            (
                "Configuration Management",
                "Flexible configuration system with YAML support",
            ),
            ("Rich Logging", "Beautiful terminal output with progress tracking"),
            ("Modular Design", "Easy to extend and maintain"),
        ]

        for component, description in architecture_info:
            self.logger.info(f"🔸 {component}")
            self.logger.info(f"   {description}")
            self.logger.info("")

    def run_full_demo(self):
        """Run the complete demo."""
        self.show_banner()

        self.logger.info(
            "🎯 Starting comprehensive demo of WiFi Jammer Tool features..."
        )
        self.logger.info("")

        # Run all demo sections
        demo_sections = [
            self.demo_interface_detection,
            self.demo_network_scanning,
            self.demo_attack_types,
            self.demo_attack_execution,
            self.demo_configuration,
            self.demo_security_features,
            self.demo_architecture,
        ]

        for demo_section in demo_sections:
            try:
                demo_section()
                time.sleep(1)  # Brief pause between sections
            except (OSError, RuntimeError, ValueError, KeyboardInterrupt) as e:
                self.logger.error(f"Demo section failed: {e}")

        # Demo completion
        self.logger.info("🎉 Demo Completed!")
        self.logger.info("=" * 50)
        self.logger.info("The WiFi Jammer Tool is now ready for use!")
        self.logger.info("")
        self.logger.info("📋 Next Steps:")
        self.logger.info("  1. Run 'python -m wifi_jammer.cli' for interactive mode")
        self.logger.info("  2. Check examples/ directory for usage examples")
        self.logger.info("  3. Run 'python run_tests.py' to verify installation")
        self.logger.info("  4. Read README.md for detailed documentation")
        self.logger.info("")
        self.logger.warning("⚠️  Remember: Use responsibly and legally!")


def main():
    """Main demo function."""
    try:
        demo = WiFiJammerDemo()
        demo.run_full_demo()
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except (OSError, RuntimeError, ValueError) as e:
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
