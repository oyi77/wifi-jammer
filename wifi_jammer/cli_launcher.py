"""GUI/TUI launch helpers for the CLI.

The launch logic for the optional PyQt6 GUI and Textual TUI was
previously duplicated verbatim in the ``cli`` group, the ``scan``
command, and the ``attack`` command.  Centralizing it here removes that
triplication and gives every entry point identical error handling.
"""

import sys
from typing import Optional, List

from rich.console import Console


def _console() -> Console:
    return Console()


def _print_not_available(feature: str, package: str, error: Optional[str]) -> None:
    console = _console()
    console.print(
        f"[red]{feature} not available. Install {package}:[/red] "
        f"[cyan]pip install {package}[/cyan]"
    )
    if error:
        console.print(f"[red]Error: {error}[/red]")


def launch_gui() -> None:
    """Launch the PyQt6 GUI if available; exits the process either way."""
    try:
        from wifi_jammer.gui import launch_gui as _launch_gui

        sys.exit(_launch_gui())
    except ImportError as e:
        _print_not_available("GUI", "PyQt6", str(e))
        sys.exit(1)


def _get_available_interfaces() -> List[str]:
    """Return names of available wireless interfaces, or exit if none."""
    from wifi_jammer.core.platform_interface import PlatformInterfaceFactory

    platform_interface = PlatformInterfaceFactory.create()
    wireless_interfaces = platform_interface.get_wireless_interfaces()
    available_interfaces = [
        iface.name for iface in wireless_interfaces if iface.status == "Available"
    ]

    if not available_interfaces:
        console = _console()
        console.print("[red]No available wireless interfaces found![/red]")
        sys.exit(1)

    return available_interfaces


def launch_tui(interface: Optional[str] = None) -> None:
    """Launch the Textual TUI if available; exits the process either way."""
    try:
        from wifi_jammer.tui import WiFiJammerApp

        available_interfaces = _get_available_interfaces()
        selected_interface = interface or available_interfaces[0]
        app = WiFiJammerApp(selected_interface)
        sys.exit(app.run())
    except ImportError as e:
        _print_not_available("TUI", "textual", str(e))
        sys.exit(1)
    except Exception as e:
        console = _console()
        console.print(f"[red]Error launching TUI: {e}[/red]")
        sys.exit(1)
