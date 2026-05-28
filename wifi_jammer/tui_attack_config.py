"""
Attack configuration screen for TUI using Textual.
"""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import (
    Header, Footer, Static, Button, Input, Select, Label, Checkbox
)
from textual.binding import Binding

from wifi_jammer.core.interfaces import AttackType, AttackConfig, NetworkInfo


class AttackConfigScreen(Screen):
    """Screen for configuring an attack before launching."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, target: NetworkInfo, interface: str):
        super().__init__()
        self.target = target
        self.interface = interface
        self.config: AttackConfig | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label(
                f"[bold cyan]Configure Attack[/bold cyan]\n"
                f"Target: [yellow]{self.target.ssid or 'Hidden'}[/yellow] ({self.target.bssid})\n"
                f"Channel: {self.target.channel} | RSSI: {self.target.rssi} dBm",
                id="config_header"
            ),
            Vertical(
                Label("Attack Type:"),
                Select(
                    [(at.value.replace("_", " ").title(), at) for at in AttackType],
                    id="attack_type",
                    value=AttackType.DEAUTH,
                ),
                Label("Target Client (blank = broadcast):"),
                Input(placeholder="ff:ff:ff:ff:ff:ff", id="target_client"),
                Label("Packet Count (0 = unlimited):"),
                Input(value="0", id="packet_count", type="integer"),
                Label("Delay between packets (seconds):"),
                Input(value="0.1", id="delay", type="number"),
                Label("Source MAC (blank = random):"),
                Input(placeholder="Auto", id="source_mac"),
                id="config_fields"
            ),
            Horizontal(
                Button("Start Attack", variant="error", id="start_attack"),
                Button("Cancel", variant="default", id="cancel"),
                id="config_buttons"
            ),
            id="attack_config_container"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.app.pop_screen()
            return

        if event.button.id == "start_attack":
            attack_type_widget = self.query_one("#attack_type", Select)
            attack_type = attack_type_widget.value if attack_type_widget.value != Select.BLANK else AttackType.DEAUTH

            target_client = self.query_one("#target_client", Input).value.strip() or ""
            count_str = self.query_one("#packet_count", Input).value.strip() or "0"
            delay_str = self.query_one("#delay", Input).value.strip() or "0.1"
            source_mac = self.query_one("#source_mac", Input).value.strip() or ""

            try:
                count = int(count_str)
            except ValueError:
                count = 0
            try:
                delay = float(delay_str)
            except ValueError:
                delay = 0.1

            self.config = AttackConfig(
                attack_type=attack_type,
                target_bssid=self.target.bssid,
                target_ssid=self.target.ssid or "",
                source_mac=source_mac,
                interface=self.interface,
                channel=self.target.channel,
                count=count,
                delay=delay,
                target_client=target_client,
                verbose=False,
            )
            self.app.pop_screen(self.config)
