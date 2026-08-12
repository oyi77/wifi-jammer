"""
Modern TUI for WiFi Jammer using Textual.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Button,
    Input,
    Log,
    Label,
)
from textual.screen import Screen
from textual.binding import Binding
import threading
import time
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from textual.widgets import Label, Log, Button, Input
    from wifi_jammer.attacks.base_attack import AttackStats
from wifi_jammer.core.interfaces import (
    NetworkInfo,
    AttackType,
    AttackConfig,
    IAttackStrategy,
)
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger


class NetworkTable(DataTable[str]):
    """A data table to display discovered networks."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.add_columns("SSID", "BSSID", "Ch", "RSSI", "Security")

    def update_networks(self, networks: List[NetworkInfo]) -> None:
        for network in networks:
            self.add_row(
                network.ssid or "Hidden",
                network.bssid,
                str(network.channel),
                f"{network.rssi} dBm",
                network.encryption,
                key=network.bssid,
            )


class ScanScreen(Screen[None]):
    """Screen for scanning networks."""

    def __init__(self, interface: Optional[str]):
        super().__init__()
        self.interface = interface

    def compose(self) -> ComposeResult:
        yield Header()
        interface_display = (
            self.interface if self.interface else "No interface selected"
        )
        yield Container(
            Label(
                f"Scanning for networks on [cyan]{interface_display}[/cyan]...",
                id="scan_status",
            ),
            NetworkTable(id="network_table"),
            Horizontal(
                Button("Stop Scan", variant="error", id="stop_scan"),
                Button("Select & Attack", variant="success", id="select_target"),
                classes="button_row",
            ),
            id="scan_container",
        )
        yield Footer()


class AttackConfigScreen(Screen[None]):
    """Screen for configuring attack parameters."""

    def __init__(self, target: NetworkInfo):
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label(
                f"[bold]Configure Attack for {self.target.ssid or 'Hidden'}[/bold]",
                id="config_title",
            ),
            Label(
                f"BSSID: {self.target.bssid} | Channel: {self.target.channel} | RSSI: {self.target.rssi} dBm"
            ),
            Label("Attack Type:"),
            DataTable(id="attack_type_table"),
            Label("Delay (seconds):"),
            Input(value="0.1", id="delay_input", placeholder="0.1"),
            Label("Packet Count (0=unlimited):"),
            Input(value="0", id="count_input", placeholder="0"),
            Label("Target Client (empty=broadcast):"),
            Input(value="", id="client_input", placeholder="ff:ff:ff:ff:ff:ff"),
            Horizontal(
                Button("Start Attack", variant="error", id="start_attack_btn"),
                Button("Cancel", variant="default", id="cancel_config_btn"),
                classes="button_row",
            ),
            id="config_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#attack_type_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Type", "Description")
        for atype in AttackType:
            desc = {
                AttackType.DEAUTH: "Kick all clients from AP",
                AttackType.DISASSOC: "Disassociate clients from AP",
                AttackType.BEACON_FLOOD: "Flood area with fake APs",
                AttackType.AUTH_FLOOD: "Flood AP with auth requests",
                AttackType.ASSOC_FLOOD: "Flood AP with association requests",
                AttackType.PROBE_RESPONSE: "Respond to all probes with fake APs",
                AttackType.CHANNEL_HOP: "Deauth across multiple channels",
                AttackType.PMKID_CAPTURE: "Capture PMKID for offline cracking",
                AttackType.EVIL_TWIN: "Spoof AP and deauth real one",
                AttackType.NETCUT: "Kick specific clients selectively",
            }.get(atype, "")
            table.add_row(atype.value, desc, key=atype.value)


class AttackScreen(Screen[None]):
    """Screen for monitoring the attack."""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label("[bold red]ATTACK IN PROGRESS[/bold red]", id="attack_title"),
                Grid(
                    Label("Packets Sent:", classes="stat_label"),
                    Label("0", id="packets_sent", classes="stat_value"),
                    Label("PPS:", classes="stat_label"),
                    Label("0.0", id="pps", classes="stat_value"),
                    Label("Success Rate:", classes="stat_label"),
                    Label("0.0%", id="success_rate", classes="stat_value"),
                    Label("Duration:", classes="stat_label"),
                    Label("0s", id="duration", classes="stat_value"),
                    id="stats_grid",
                ),
                Label("Activity Log:", id="log_label"),
                Log(id="attack_log"),
                Button("STOP ATTACK", variant="error", id="stop_attack"),
                id="attack_vbox",
            )
        )
        yield Footer()


class WiFiJammerApp(App[None]):
    """Main WiFi Jammer TUI application."""

    CSS = """
    #scan_container {
        padding: 1;
    }
    .button_row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    .button_row Button {
        margin: 0 1;
    }
    #stats_grid {
        grid-size: 2 4;
        grid-columns: 1fr 1fr;
        height: 10;
        border: heavy $accent;
        padding: 1;
        margin-top: 1;
    }
    .stat_label {
        color: $text-muted;
    }
    .stat_value {
        text-style: bold;
        color: $secondary;
    }
    #attack_log {
        height: 1fr;
        border: solid $accent;
        margin-top: 1;
    }
    #attack_vbox {
        padding: 1;
    }
    #attack_title {
        text-align: center;
        width: 100%;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh Scan"),
    ]

    def __init__(self, interface: Optional[str] = None) -> None:
        super().__init__()
        self.interface: Optional[str] = interface
        # Use quiet logger for TUI to avoid cluttering the interface
        self.logger = RichLogger(quiet=True)
        # Ensure scanner uses system Python with permission on macOS
        self.scanner = ScapyNetworkScanner(logger=self.logger)
        self.factory = AttackFactory()
        self.current_attack: Optional["IAttackStrategy"] = None
        self.networks: List[NetworkInfo] = []
        self._scanning = False
        self._scan_thread: Optional[threading.Thread] = None
        self.platform_interface = PlatformInterfaceFactory.create()
        self._permission_warning: Optional[str] = None
        # If no interface provided, try to get one
        if not self.interface:
            wireless_interfaces = self.platform_interface.get_wireless_interfaces()
            available_interfaces = [
                iface.name
                for iface in wireless_interfaces
                if iface.status == "Available"
            ]
            if available_interfaces:
                self.interface = available_interfaces[0]

        # Check and warn about Python/permission on macOS
        import platform

        if platform.system() == "Darwin":
            from wifi_jammer.utils.python_detector import (
                find_python_with_permission,
                test_wifi_access,
            )
            import sys

            python_with_permission = find_python_with_permission()
            current_python = sys.executable

            if python_with_permission and python_with_permission != current_python:
                # Log warning but don't block - TUI should still work
                has_access, ssid, bssid = test_wifi_access(current_python)
                if not has_access:
                    # Store warning to show in status
                    self._permission_warning = f"Using {current_python} (no permission). System Python {python_with_permission} has permission."
                else:
                    self._permission_warning = None
            else:
                self._permission_warning = None
        else:
            self._permission_warning = None

    def compose(self) -> ComposeResult:
        yield Header()
        interface_display = (
            self.interface if self.interface else "No interface selected"
        )
        yield Container(
            Label(
                f"Welcome to WiFi Jammer Tool v2.0 - [cyan]{interface_display}[/cyan]"
            ),
            Button("Start Scanning", variant="primary", id="start_scan_btn"),
            Button("Select Interface", variant="default", id="select_interface_btn"),
            id="welcome_container",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_scan_btn":
            if not self.interface:
                self._select_interface()
                if not self.interface:
                    return
            scan_screen = ScanScreen(self.interface)
            self.push_screen(scan_screen)
            self.start_scanning()
        elif event.button.id == "select_interface_btn":
            self._select_interface()
        elif event.button.id == "stop_scan":
            self._scanning = False
            self.update_scan_status("Scan stopped")
        elif event.button.id == "select_target":
            # Query from current screen (ScanScreen) not app level
            try:
                current_screen = self.screen
                table = current_screen.query_one(NetworkTable)
                if table.cursor_row is not None and table.cursor_row < len(
                    self.networks
                ):
                    bssid = table.get_row_at(table.cursor_row)[1]
                    target = next((n for n in self.networks if n.bssid == bssid), None)
                    if target:
                        self.show_attack_config(target)
                    else:
                        # Show message if no target selected
                        self.update_scan_status(
                            "[yellow]Please select a network from the table first[/yellow]"
                        )
                else:
                    self.update_scan_status(
                        "[yellow]Please select a network from the table first[/yellow]"
                    )
            except Exception as e:
                # If table not found, show helpful message
                self.update_scan_status(
                    f"[red]Error: Could not find network table. {e}[/red]"
                )
        elif event.button.id == "start_attack_btn":
            self._start_attack_from_config()
        elif event.button.id == "cancel_config_btn":
            self.pop_screen()
        elif event.button.id == "stop_attack":
            if self.current_attack:
                self.current_attack.stop()
            self.pop_screen()

    def start_scanning(self) -> None:
        # Ensure we have an interface
        if not self.interface:
            self._select_interface()
            if not self.interface:
                self.update_scan_status(
                    "[red]No interface available. Cannot start scanning.[/red]"
                )
                return

        # Show permission warning if applicable
        if hasattr(self, "_permission_warning") and self._permission_warning:
            self.update_scan_status(f"[yellow]⚠️  {self._permission_warning}[/yellow]")
            time.sleep(2)  # Show warning briefly

        self._scanning = True
        self._scan_thread = threading.Thread(target=self._scan_loop)
        self._scan_thread.daemon = True
        self._scan_thread.start()

    def _scan_loop(self) -> None:
        scan_count = 0
        last_error: Optional[str] = None
        while self._scanning:
            try:
                scan_count += 1
                status_msg = f"Scanning on {self.interface}... (attempt {scan_count})"
                self.call_from_thread(self.update_scan_status, status_msg)

                # Perform scan with timeout protection
                import threading

                networks = []
                scan_error = None

                def _do_scan() -> None:
                    nonlocal networks, scan_error
                    try:
                        if self.interface is not None:
                            networks = self.scanner.scan_networks(self.interface)
                        else:
                            scan_error = "No interface selected"
                    except Exception as e:
                        scan_error = str(e)

                scan_thread = threading.Thread(target=_do_scan)
                scan_thread.daemon = True
                scan_thread.start()
                scan_thread.join(timeout=30)  # 30 second timeout

                if scan_thread.is_alive():
                    # Scan is taking too long
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[yellow]Scan taking longer than expected... (attempt {scan_count})[/yellow]",
                    )
                    time.sleep(2)
                    continue

                if scan_error:
                    raise Exception(scan_error)

                # Check if networks were blocked by privacy
                privacy_blocked = getattr(self.scanner, "_privacy_blocked_count", 0)

                if networks:
                    self.networks = networks
                    self.call_from_thread(self.update_network_list)
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[green]Found {len(networks)} network(s) on {self.interface}[/green]",
                    )
                    last_error = None  # Clear previous error on success
                elif privacy_blocked > 0:
                    # Networks were found but blocked by privacy
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[yellow]⚠️  {privacy_blocked} network(s) detected but blocked by privacy[/yellow]\n"
                        "[dim]Location Services permission required to see SSID/BSSID[/dim]\n"
                        "[cyan]Fix: Run 'bash install.sh' or grant permission in System Settings[/cyan]",
                    )
                    last_error = f"{privacy_blocked} networks blocked by privacy"
                elif last_error and (
                    "privacy" in last_error.lower()
                    or "permission" in last_error.lower()
                ):
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[red]Permission issue: {last_error}[/red]\n"
                        "[dim]Fix: System Settings → Privacy → Location Services → Enable for Python[/dim]",
                    )
                elif last_error:
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[yellow]No networks found... (attempt {scan_count}) - {last_error}[/yellow]",
                    )
                else:
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[dim]Scanning... (attempt {scan_count}) - No networks found yet[/dim]",
                    )
            except Exception as e:
                error_msg = str(e)
                last_error = error_msg

                # Check if it's a permission/privacy issue
                if (
                    "privacy" in error_msg.lower()
                    or "permission" in error_msg.lower()
                    or "location" in error_msg.lower()
                ):
                    self.call_from_thread(
                        self.update_scan_status,
                        f"[red]⚠️  Location Services Permission Required[/red]\n"
                        f"[dim]Error: {error_msg}[/dim]\n"
                        "[yellow]Fix: Run 'bash install.sh' or grant permission in System Settings[/yellow]",
                    )
                else:
                    self.call_from_thread(
                        self.update_scan_status, f"[red]Error: {error_msg}[/red]"
                    )

                # Log to console for debugging
                import sys

                print(f"TUI Scan Error (attempt {scan_count}): {e}", file=sys.stderr)
                import traceback

                traceback.print_exc(file=sys.stderr)

            time.sleep(3)  # Wait 3 seconds between scans

    def update_scan_status(self, message: str) -> None:
        """Update the scan status label."""
        try:
            # Query from current screen (ScanScreen) not app level
            current_screen = self.screen
            if isinstance(current_screen, ScanScreen):
                status_label = current_screen.query_one(
                    "#scan_status", expect_type=Label
                )
                status_label.update(message)
        except Exception:
            # If we can't find the label, it's okay - might be on different screen
            pass

    def update_network_list(self) -> None:
        """Update the network table with scan results."""
        try:
            # Query from current screen (ScanScreen) not app level
            current_screen = self.screen
            if isinstance(current_screen, ScanScreen):
                table = current_screen.query_one(NetworkTable)
                table.update_networks(self.networks)
        except Exception as e:
            # Log error but don't crash - might be on wrong screen
            import sys

            print(f"TUI Update Error: {e}", file=sys.stderr)

    def show_attack_config(self, target: NetworkInfo) -> None:
        self.push_screen(AttackConfigScreen(target))

    def _start_attack_from_config(self) -> None:
        """Read config screen inputs and start attack."""
        try:
            screen = self.screen
            if not isinstance(screen, AttackConfigScreen):
                return

            # Get selected attack type from table
            table = screen.query_one("#attack_type_table", DataTable)
            if table.cursor_row is None:
                return
            attack_type_name = list(AttackType)[table.cursor_row]

            delay = float(screen.query_one("#delay_input", Input).value or "0.1")
            count = int(screen.query_one("#count_input", Input).value or "0")
            client = screen.query_one("#client_input", Input).value or ""

            config = AttackConfig(
                attack_type=attack_type_name,
                target_bssid=screen.target.bssid,
                target_ssid=screen.target.ssid or "",
                interface=self.interface or "",
                channel=screen.target.channel,
                count=count,
                delay=delay,
                target_client=client,
            )

            self.pop_screen()
            self.push_screen(AttackScreen())
            self.run_attack(config)
        except Exception as e:
            import sys

            print(f"Config error: {e}", file=sys.stderr)

    def run_attack(self, config: AttackConfig) -> None:
        self.current_attack = self.factory.create_attack(config.attack_type)
        self.current_attack.set_progress_callback(self.update_stats)

        def _exec() -> None:
            if self.current_attack is not None:
                self.current_attack.execute(config)
                while self.current_attack.is_running():
                    time.sleep(1)

        attack_thread = threading.Thread(target=_exec)
        attack_thread.daemon = True
        attack_thread.start()

    def update_stats(self, stats: "AttackStats") -> None:
        try:
            self.call_from_thread(self._update_ui_stats, stats)
        except (AttributeError, RuntimeError, ValueError):
            # UI update failed - screen may not be ready or stats invalid
            pass

    def _update_ui_stats(self, stats: "AttackStats") -> None:
        screen = self.screen
        if isinstance(screen, AttackScreen):
            packets_sent = screen.query_one("#packets_sent", expect_type=Label)
            pps = screen.query_one("#pps", expect_type=Label)
            success_rate = screen.query_one("#success_rate", expect_type=Label)
            duration = screen.query_one("#duration", expect_type=Label)
            packets_sent.update(str(stats.packets_sent))
            pps.update(f"{stats.packets_per_second:.1f}")
            success_rate.update(f"{stats.success_rate:.1f}%")
            duration.update(f"{stats.duration:.1f}s")

            log = screen.query_one("#attack_log", expect_type=Log)
            if stats.errors and len(stats.errors) > 0:
                log.write_line(f"[red]Error: {stats.errors[-1]}[/red]")
            else:
                log.write_line(f"Sent {stats.packets_sent} packets...")

    def _select_interface(self) -> None:
        """Select interface from available wireless interfaces."""
        wireless_interfaces = self.platform_interface.get_wireless_interfaces()
        available_interfaces = [
            iface.name for iface in wireless_interfaces if iface.status == "Available"
        ]

        if not available_interfaces:
            # Show error message
            try:
                welcome_label = self.query_one(
                    "#welcome_container Label", expect_type=Label
                )
                welcome_label.update(
                    "[red]No available wireless interfaces found![/red]\n"
                    "[dim]Please ensure you have a wireless adapter connected.[/dim]"
                )
            except (AttributeError, ValueError, RuntimeError):
                # UI element not found or update failed
                pass
            return

        # If only one interface, use it automatically
        if len(available_interfaces) == 1:
            self.interface = available_interfaces[0]
            try:
                welcome_label = self.query_one(
                    "#welcome_container Label", expect_type=Label
                )
                welcome_label.update(
                    f"Welcome to WiFi Jammer Tool v2.0 - [cyan]{self.interface}[/cyan]"
                )
            except (AttributeError, ValueError, RuntimeError):
                # UI element not found or update failed
                pass
        else:
            # For multiple interfaces, use the first one for now
            # In a full implementation, you'd show a selection dialog
            self.interface = available_interfaces[0]
            try:
                welcome_label = self.query_one(
                    "#welcome_container Label", expect_type=Label
                )
                welcome_label.update(
                    f"Welcome to WiFi Jammer Tool v2.0 - [cyan]{self.interface}[/cyan]\n"
                    f"[dim]Note: Using first available interface. {len(available_interfaces)} interfaces found.[/dim]"
                )
            except (AttributeError, ValueError, RuntimeError):
                # UI element not found or update failed
                pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        app = WiFiJammerApp(sys.argv[1])
        app.run()
    else:
        print("Usage: python3 -m wifi_jammer.tui <interface>")
