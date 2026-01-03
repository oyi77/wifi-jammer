"""
Modern TUI for WiFi Jammer using Textual.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Header, Footer, Static, DataTable, Button, Input, Log, Label, Sparkline
from textual.screen import Screen
from textual.binding import Binding
from textual.message import Message
import threading
import time
from typing import List, Optional

from wifi_jammer.core.interfaces import NetworkInfo, AttackType, AttackConfig
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger

class NetworkTable(DataTable):
    """A data table to display discovered networks."""
    
    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.add_columns("SSID", "BSSID", "Ch", "RSSI", "Security")

    def update_networks(self, networks: List[NetworkInfo]):
        self.clear()
        for network in networks:
            self.add_row(
                network.ssid or "Hidden",
                network.bssid,
                str(network.channel),
                f"{network.rssi} dBm",
                network.encryption,
                key=network.bssid
            )

class ScanScreen(Screen):
    """Screen for scanning networks."""
    
    def __init__(self, interface: Optional[str]):
        super().__init__()
        self.interface = interface
    
    def compose(self) -> ComposeResult:
        yield Header()
        interface_display = self.interface if self.interface else "No interface selected"
        yield Container(
            Label(f"Scanning for networks on [cyan]{interface_display}[/cyan]...", id="scan_status"),
            NetworkTable(id="network_table"),
            Horizontal(
                Button("Stop Scan", variant="error", id="stop_scan"),
                Button("Select & Attack", variant="success", id="select_target"),
                classes="button_row"
            ),
            id="scan_container"
        )
        yield Footer()

class AttackScreen(Screen):
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
                    id="stats_grid"
                ),
                Label("Activity Log:", id="log_label"),
                Log(id="attack_log"),
                Button("STOP ATTACK", variant="error", id="stop_attack"),
                id="attack_vbox"
            )
        )
        yield Footer()

class WiFiJammerApp(App):
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

    def __init__(self, interface: Optional[str] = None):
        super().__init__()
        self.interface = interface
        # Use quiet logger for TUI to avoid cluttering the interface
        self.logger = RichLogger(quiet=True)
        # Ensure scanner uses system Python with permission on macOS
        self.scanner = ScapyNetworkScanner(logger=self.logger)
        self.factory = AttackFactory()
        self.current_attack = None
        self.networks = []
        self._scanning = False
        self._scan_thread = None
        self.platform_interface = PlatformInterfaceFactory.create()
        
        # If no interface provided, try to get one
        if not self.interface:
            wireless_interfaces = self.platform_interface.get_wireless_interfaces()
            available_interfaces = [iface.name for iface in wireless_interfaces 
                                  if iface.status == "Available"]
            if available_interfaces:
                self.interface = available_interfaces[0]
        
        # Check and warn about Python/permission on macOS
        import platform
        if platform.system() == "Darwin":
            from wifi_jammer.utils.python_detector import find_python_with_permission, test_wifi_access
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
        interface_display = self.interface if self.interface else "No interface selected"
        yield Container(
            Label(f"Welcome to WiFi Jammer Tool v2.0 - [cyan]{interface_display}[/cyan]"),
            Button("Start Scanning", variant="primary", id="start_scan_btn"),
            Button("Select Interface", variant="default", id="select_interface_btn"),
            id="welcome_container"
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
                if table.cursor_row is not None and table.cursor_row < len(self.networks):
                    bssid = table.get_row_at(table.cursor_row)[1]
                    target = next((n for n in self.networks if n.bssid == bssid), None)
                    if target:
                        self.show_attack_config(target)
                    else:
                        # Show message if no target selected
                        self.update_scan_status("[yellow]Please select a network from the table first[/yellow]")
                else:
                    self.update_scan_status("[yellow]Please select a network from the table first[/yellow]")
            except Exception as e:
                # If table not found, show helpful message
                self.update_scan_status(f"[red]Error: Could not find network table. {e}[/red]")
        elif event.button.id == "stop_attack":
            if self.current_attack:
                self.current_attack.stop()
            self.pop_screen()

    def start_scanning(self):
        # Ensure we have an interface
        if not self.interface:
            self._select_interface()
            if not self.interface:
                self.update_scan_status("[red]No interface available. Cannot start scanning.[/red]")
                return
        
        # Show permission warning if applicable
        if hasattr(self, '_permission_warning') and self._permission_warning:
            self.update_scan_status(f"[yellow]⚠️  {self._permission_warning}[/yellow]")
            time.sleep(2)  # Show warning briefly
        
        self._scanning = True
        self._scan_thread = threading.Thread(target=self._scan_loop)
        self._scan_thread.daemon = True
        self._scan_thread.start()

    def _scan_loop(self):
        scan_count = 0
        last_error = None
        while self._scanning:
            try:
                scan_count += 1
                status_msg = f"Scanning on {self.interface}... (attempt {scan_count})"
                self.call_from_thread(self.update_scan_status, status_msg)
                
                # Perform scan with timeout protection
                import signal
                import threading
                
                networks = []
                scan_error = None
                
                def _do_scan():
                    nonlocal networks, scan_error
                    try:
                        networks = self.scanner.scan_networks(self.interface)
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
                        f"[yellow]Scan taking longer than expected... (attempt {scan_count})[/yellow]"
                    )
                    time.sleep(2)
                    continue
                
                if scan_error:
                    raise Exception(scan_error)
                
                # Check if networks were blocked by privacy
                privacy_blocked = getattr(self.scanner, '_privacy_blocked_count', 0)
                
                if networks:
                    self.networks = networks
                    self.call_from_thread(self.update_network_list)
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[green]Found {len(networks)} network(s) on {self.interface}[/green]"
                    )
                    last_error = None  # Clear previous error on success
                elif privacy_blocked > 0:
                    # Networks were found but blocked by privacy
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[yellow]⚠️  {privacy_blocked} network(s) detected but blocked by privacy[/yellow]\n"
                        "[dim]Location Services permission required to see SSID/BSSID[/dim]\n"
                        "[cyan]Fix: Run 'bash install.sh' or grant permission in System Settings[/cyan]"
                    )
                    last_error = f"{privacy_blocked} networks blocked by privacy"
                elif last_error and ("privacy" in last_error.lower() or "permission" in last_error.lower()):
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[red]Permission issue: {last_error}[/red]\n"
                        "[dim]Fix: System Settings → Privacy → Location Services → Enable for Python[/dim]"
                    )
                elif last_error:
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[yellow]No networks found... (attempt {scan_count}) - {last_error}[/yellow]"
                    )
                else:
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[dim]Scanning... (attempt {scan_count}) - No networks found yet[/dim]"
                    )
            except Exception as e:
                error_msg = str(e)
                last_error = error_msg
                
                # Check if it's a permission/privacy issue
                if "privacy" in error_msg.lower() or "permission" in error_msg.lower() or "location" in error_msg.lower():
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[red]⚠️  Location Services Permission Required[/red]\n"
                        f"[dim]Error: {error_msg}[/dim]\n"
                        "[yellow]Fix: Run 'bash install.sh' or grant permission in System Settings[/yellow]"
                    )
                else:
                    self.call_from_thread(
                        self.update_scan_status, 
                        f"[red]Error: {error_msg}[/red]"
                    )
                
                # Log to console for debugging
                import sys
                print(f"TUI Scan Error (attempt {scan_count}): {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
            
            time.sleep(3)  # Wait 3 seconds between scans

    def update_scan_status(self, message: str):
        """Update the scan status label."""
        try:
            # Query from current screen (ScanScreen) not app level
            current_screen = self.screen
            if isinstance(current_screen, ScanScreen):
                status_label = current_screen.query_one("#scan_status", expect_type=Label)
                status_label.update(message)
        except Exception as e:
            # If we can't find the label, it's okay - might be on different screen
            pass

    def update_network_list(self):
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

    def show_attack_config(self, target: NetworkInfo):
        # In a real app, you'd show a config screen. 
        # For now, let's start a default deauth attack.
        self._scanning = False
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid=target.bssid,
            interface=self.interface,
            channel=target.channel,
            delay=0.1
        )
        self.push_screen(AttackScreen())
        self.run_attack(config)

    def run_attack(self, config: AttackConfig):
        self.current_attack = self.factory.create_attack(config.attack_type, logger=self.logger)
        self.current_attack.set_progress_callback(self.update_stats)
        
        def _exec():
            self.current_attack.execute(config)
            while self.current_attack.is_running():
                time.sleep(1)
        
        attack_thread = threading.Thread(target=_exec)
        attack_thread.daemon = True
        attack_thread.start()

    def update_stats(self, stats):
        try:
            self.call_from_thread(self._update_ui_stats, stats)
        except (AttributeError, RuntimeError, ValueError):
            # UI update failed - screen may not be ready or stats invalid
            pass

    def _update_ui_stats(self, stats):
        screen = self.screen
        if isinstance(screen, AttackScreen):
            screen.query_one("#packets_sent").update(str(stats.packets_sent))
            screen.query_one("#pps").update(f"{stats.packets_per_second:.1f}")
            screen.query_one("#success_rate").update(f"{stats.success_rate:.1f}%")
            screen.query_one("#duration").update(f"{stats.duration:.1f}s")
            
            log = screen.query_one("#attack_log")
            if stats.errors and len(stats.errors) > 0:
                log.write_line(f"[red]Error: {stats.errors[-1]}[/red]")
            else:
                log.write_line(f"Sent {stats.packets_sent} packets...")
    
    def _select_interface(self):
        """Select interface from available wireless interfaces."""
        wireless_interfaces = self.platform_interface.get_wireless_interfaces()
        available_interfaces = [iface.name for iface in wireless_interfaces 
                              if iface.status == "Available"]
        
        if not available_interfaces:
            # Show error message
            try:
                welcome_label = self.query_one("#welcome_container Label")
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
                welcome_label = self.query_one("#welcome_container Label")
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
                welcome_label = self.query_one("#welcome_container Label")
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
