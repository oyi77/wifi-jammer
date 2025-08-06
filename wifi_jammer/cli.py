#!/usr/bin/env python3
"""
Command-line interface for WiFi jamming tool.
"""

import sys
import os
import signal
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

from .core.interfaces import AttackType, AttackConfig
from .scanner import ScapyNetworkScanner
from .factory import AttackFactory
from .utils import RichLogger


class WiFiJammerCLI:
    """Main CLI class for WiFi jamming tool."""
    
    def __init__(self):
        self.console = Console()
        self.logger = RichLogger()
        self.scanner = ScapyNetworkScanner(self.logger)
        self.factory = AttackFactory()
        self.current_attack = None
    
    def check_root(self):
        """Check if running as root."""
        import platform
        
        if platform.system() == "Windows":
            # Windows - check for admin privileges
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self.logger.warning("Some features may require administrator privileges on Windows.")
            except:
                self.logger.warning("Could not check Windows privileges.")
        else:
            # Unix-like systems
            if os.geteuid() != 0:
                self.logger.warning("Some features require root privileges. Run with sudo for full functionality.")
                # Don't exit, just warn
    
    def show_banner(self):
        """Display tool banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    WiFi Jammer Tool                          ║
║              Advanced WiFi Jamming Utility                   ║
║                    By Paijo - v1.0.0                        ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="cyan"))
    
    def list_interfaces(self):
        """List available wireless interfaces."""
        interfaces = self.scanner.get_interface_list()
        
        if not interfaces:
            self.logger.error("No wireless interfaces found!")
            return None
        
        table = Table(title="Available Wireless Interfaces")
        table.add_column("Interface", style="cyan")
        table.add_column("Status", style="green")
        
        for iface in interfaces:
            status = "Available" if os.path.exists(f"/sys/class/net/{iface}") else "Not Available"
            table.add_row(iface, status)
        
        self.console.print(table)
        return interfaces
    
    def scan_networks(self, interface: str, channel: int = None):
        """Scan for available networks."""
        self.logger.info(f"Scanning networks on {interface}...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            networks = self.scanner.scan_networks(interface, channel)
            progress.update(task, completed=True)
        
        return networks
    
    def display_networks(self, networks):
        """Display scanned networks in a table."""
        if not networks:
            self.logger.warning("No networks found!")
            return
        
        table = Table(title="Available Networks")
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="yellow")
        table.add_column("Channel", style="green")
        table.add_column("RSSI", style="red")
        table.add_column("Encryption", style="blue")
        
        for network in networks:
            table.add_row(
                network.ssid or "Hidden",
                network.bssid,
                str(network.channel),
                f"{network.rssi} dBm",
                network.encryption
            )
        
        self.console.print(table)
    
    def select_network(self, networks):
        """Let user select a target network."""
        if not networks:
            return None
        
        choices = []
        for i, network in enumerate(networks, 1):
            choice = f"{i}. {network.ssid or 'Hidden'} ({network.bssid}) - Ch{network.channel}"
            choices.append(choice)
        
        self.console.print("\nSelect target network:")
        for choice in choices:
            self.console.print(f"  {choice}")
        
        while True:
            try:
                selection = Prompt.ask("Enter number", default="1")
                index = int(selection) - 1
                if 0 <= index < len(networks):
                    return networks[index]
                else:
                    self.logger.error("Invalid selection!")
            except ValueError:
                self.logger.error("Please enter a valid number!")
    
    def select_attack(self):
        """Let user select attack type."""
        attacks = self.factory.get_available_attacks()
        
        self.console.print("\nAvailable attacks:")
        for i, attack in enumerate(attacks, 1):
            self.console.print(f"  {i}. {attack.value}")
        
        while True:
            try:
                selection = Prompt.ask("Select attack type", default="1")
                index = int(selection) - 1
                if 0 <= index < len(attacks):
                    return attacks[index]
                else:
                    self.logger.error("Invalid selection!")
            except ValueError:
                self.logger.error("Please enter a valid number!")
    
    def configure_attack(self, target_network, attack_type):
        """Configure attack parameters."""
        config = AttackConfig(
            attack_type=attack_type,
            target_bssid=target_network.bssid,
            target_ssid=target_network.ssid,
            channel=target_network.channel
        )
        
        # Get interface
        interfaces = self.scanner.get_interface_list()
        if interfaces:
            config.interface = Prompt.ask("Interface", default=interfaces[0])
        
        # Get packet count
        count = Prompt.ask("Packet count (0 for unlimited)", default="0")
        config.count = int(count) if count.isdigit() else 0
        
        # Get delay
        delay = Prompt.ask("Delay between packets (seconds)", default="0.1")
        config.delay = float(delay)
        
        # Get source MAC
        config.source_mac = Prompt.ask("Source MAC (random if empty)", default="")
        
        # Verbose mode
        config.verbose = Confirm.ask("Verbose mode?")
        
        return config
    
    def start_attack(self, config):
        """Start the attack."""
        try:
            attack = self.factory.create_attack(config.attack_type)
            self.current_attack = attack
            
            if attack.execute(config):
                self.logger.success(f"Attack started successfully!")
                self.logger.info("Press Ctrl+C to stop the attack")
                
                # Wait for user to stop
                try:
                    while attack.is_running():
                        import time
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.stop_attack()
            else:
                self.logger.error("Failed to start attack!")
                
        except Exception as e:
            self.logger.error(f"Error starting attack: {e}")
    
    def stop_attack(self):
        """Stop the current attack."""
        if self.current_attack and self.current_attack.is_running():
            self.current_attack.stop()
            self.logger.info("Attack stopped by user")
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        self.stop_attack()
        sys.exit(0)


@click.command()
@click.option('--interface', '-i', help='Wireless interface to use')
@click.option('--target', '-t', help='Target BSSID')
@click.option('--attack', '-a', type=click.Choice([at.value for at in AttackType]), help='Attack type')
@click.option('--count', '-c', default=0, help='Number of packets to send (0 for unlimited)')
@click.option('--delay', '-d', default=0.1, help='Delay between packets in seconds')
@click.option('--channel', '-ch', type=int, help='Channel to use')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--scan-only', is_flag=True, help='Only scan networks, don\'t attack')
def main(interface, target, attack, count, delay, channel, verbose, scan_only):
    """Advanced WiFi Jamming Tool - By Paijo"""
    
    cli = WiFiJammerCLI()
    
    # Check root privileges
    cli.check_root()
    
    # Show banner
    cli.show_banner()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, cli.signal_handler)
    signal.signal(signal.SIGTERM, cli.signal_handler)
    
    try:
        # List interfaces
        interfaces = cli.list_interfaces()
        if not interfaces:
            return
        
        # Select interface if not provided
        if not interface:
            interface = Prompt.ask("Select interface", choices=interfaces, default=interfaces[0])
        
        # Scan networks
        networks = cli.scan_networks(interface, channel)
        cli.display_networks(networks)
        
        if scan_only:
            return
        
        # Select target network
        target_network = cli.select_network(networks)
        if not target_network:
            return
        
        # Select attack type
        if not attack:
            attack_type = cli.select_attack()
        else:
            attack_type = AttackType(attack)
        
        # Configure attack
        config = AttackConfig(
            attack_type=attack_type,
            target_bssid=target_network.bssid,
            target_ssid=target_network.ssid,
            channel=target_network.channel,
            interface=interface,
            count=count,
            delay=delay,
            verbose=verbose
        )
        
        # Start attack
        cli.start_attack(config)
        
    except KeyboardInterrupt:
        cli.logger.info("Operation cancelled by user")
    except Exception as e:
        cli.logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main() 