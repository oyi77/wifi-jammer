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
from wifi_jammer.cli_session import WiFiJammerCLI
from wifi_jammer.cli_launcher import launch_gui, launch_tui

if TYPE_CHECKING:
    from wifi_jammer.attacks.base_attack import AttackStats
    from wifi_jammer.core.interfaces import NetworkInfo


# Setup warning suppression
setup_warning_suppression()



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
