#!/usr/bin/env python3
"""
Command-line interface for WiFi jamming tool.
"""

import sys
import os
import signal
import platform
import time
import threading
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from .core.interfaces import AttackType, AttackConfig
from .core.platform_interface import PlatformInterfaceFactory
from .scanner import ScapyNetworkScanner
from .factory import AttackFactory
from .utils import RichLogger
from .utils.warning_suppressor import setup_warning_suppression


# Setup warning suppression
setup_warning_suppression()


class AttackProgressDisplay:
    """Real-time attack progress display."""
    
    def __init__(self, console: Console):
        self.console = console
        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats", size=8),
            Layout(name="footer", size=3)
        )
        
        self.layout["header"].update(Panel(
            "[bold cyan]WiFi Jammer Attack in Progress[/bold cyan]\n"
            "Press Ctrl+C to stop the attack",
            style="cyan"
        ))
        
        self.layout["footer"].update(Panel(
            "[yellow]Monitoring attack progress...[/yellow]",
            style="yellow"
        ))
    
    def update_stats(self, stats):
        """Update the statistics display."""
        duration = stats.duration
        pps = stats.packets_per_second
        success_rate = stats.success_rate
        
        stats_text = f"""
[bold]Attack Statistics:[/bold]

[cyan]Packets Sent:[/cyan] {stats.packets_sent:,}
[cyan]Packets Failed:[/cyan] {stats.packets_failed:,}
[cyan]Success Rate:[/cyan] {success_rate:.1f}%
[cyan]Packets/Second:[/cyan] {pps:.1f}
[cyan]Duration:[/cyan] {duration:.1f}s

[bold]Progress Bar:[/bold]
"""
        
        # Create progress bar
        if stats.packets_sent > 0:
            progress_bar = "█" * min(50, int(stats.packets_sent / 10)) + "░" * (50 - min(50, int(stats.packets_sent / 10)))
            stats_text += f"[green]{progress_bar}[/green] {stats.packets_sent:,} packets"
        else:
            stats_text += "[red]No packets sent yet[/red]"
        
        if stats.errors:
            stats_text += f"\n\n[red]Recent Errors:[/red]\n"
            for error in stats.errors[-3:]:  # Show last 3 errors
                stats_text += f"• {error}\n"
        
        self.layout["stats"].update(Panel(stats_text, title="Live Statistics", style="blue"))
    
    def get_layout(self):
        """Get the current layout."""
        return self.layout


class WiFiJammerCLI:
    """Main CLI class for WiFi jamming tool."""
    
    def __init__(self):
        self.console = Console()
        self.logger = RichLogger()
        self.scanner = ScapyNetworkScanner(self.logger)
        self.factory = AttackFactory()
        self.current_attack = None
        self.platform_interface = PlatformInterfaceFactory.create()
        self.progress_display = None
        self.live_display = None
    
    def check_root(self):
        """Check if running as root."""
        import platform
        
        if platform.system() == "Windows":
            # Windows - check for admin privileges
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self.logger.warning("Some features may require administrator privileges on Windows.")
                    return False
                return True
            except:
                self.logger.warning("Could not check Windows privileges.")
                return False
        else:
            # Unix-like systems
            if os.geteuid() != 0:
                self.logger.warning("Some features require root privileges. Run with sudo for full functionality.")
                return False
            return True
    
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
        # Get all interfaces first
        all_interfaces = self.platform_interface.get_all_interfaces()
        wireless_interfaces = self.platform_interface.get_wireless_interfaces()
        
        if not all_interfaces:
            self.logger.error("No network interfaces found!")
            return None
        
        # Create table with all interfaces
        table = Table(title="Available Network Interfaces")
        table.add_column("Interface", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Type", style="blue")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Capabilities", style="magenta")
        
        # Add all interfaces to table
        for iface in all_interfaces:
            capabilities = ", ".join(iface.capabilities) if iface.capabilities else "None"
            table.add_row(
                iface.name,
                iface.status,
                iface.type,
                iface.mac_address,
                capabilities
            )
        
        self.console.print(table)
        
        # Return only wireless interface names for further use
        wireless_names = [iface.name for iface in wireless_interfaces if iface.status == "Available"]
        
        if not wireless_names:
            self.logger.warning("No available wireless interfaces found!")
            self.logger.info("This tool requires wireless interfaces for full functionality.")
            return []
        
        return wireless_names
    
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
    
    def configure_attack(self, attack_type):
        """Configure attack parameters."""
        config = AttackConfig(
            attack_type=attack_type,
            target_bssid="",
            target_ssid="",
            channel=0
        )
        
        # Get target BSSID
        config.target_bssid = Prompt.ask("Target BSSID")
        
        # Get interface
        interfaces = self.scanner.get_interface_list()
        if interfaces:
            config.interface = Prompt.ask("Interface", default=interfaces[0])
        
        # Get channel
        channel = Prompt.ask("Channel", default="0")
        config.channel = int(channel) if channel.isdigit() else 0
        
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
    
    def progress_callback(self, stats):
        """Callback for progress updates."""
        if self.progress_display:
            self.progress_display.update_stats(stats)
    
    def start_attack(self, config):
        """Start the attack with real-time progress display."""
        try:
            attack = self.factory.create_attack(config.attack_type)
            self.current_attack = attack
            
            # Set up progress callback
            attack.set_progress_callback(self.progress_callback)
            
            if attack.execute(config):
                self.logger.success(f"Attack started successfully!")
                
                # Create progress display
                self.progress_display = AttackProgressDisplay(self.console)
                
                # Start live display
                with Live(self.progress_display.get_layout(), refresh_per_second=2) as live:
                    self.live_display = live
                    
                    try:
                        while attack.is_running():
                            time.sleep(0.5)
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
    if not cli.check_root():
        sys.exit(1) # Exit if root privileges are not available
    
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
        config = cli.configure_attack(attack_type)
        
        # Start attack
        cli.start_attack(config)
        
    except KeyboardInterrupt:
        cli.logger.info("Operation cancelled by user")
    except Exception as e:
        cli.logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main() 