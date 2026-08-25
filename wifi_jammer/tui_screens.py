"""Screens and widgets for the WiFi Jammer Textual UI.

Split from tui.py: scan, attack-config and attack-monitoring screens.
"""

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
    from wifi_jammer.attacks.base_attack import AttackStats
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger


from wifi_jammer.core.interfaces import (
    NetworkInfo,
    AttackType,
)


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
    from wifi_jammer.attacks.base_attack import AttackStats
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


