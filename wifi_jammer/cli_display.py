"""Rich-based display components for the CLI."""

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout

if TYPE_CHECKING:
    from wifi_jammer.attacks.base_attack import AttackStats


class AttackProgressDisplay:
    """Real-time attack progress display."""

    def __init__(self, console: Console):
        self.console = console
        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats", size=8),
            Layout(name="footer", size=3),
        )

        self.layout["header"].update(
            Panel(
                "[bold cyan]WiFi Jammer Attack in Progress[/bold cyan]\n"
                "Press Ctrl+C to stop the attack",
                style="cyan",
            )
        )

        self.layout["footer"].update(
            Panel("[yellow]Monitoring attack progress...[/yellow]", style="yellow")
        )

    def update_stats(self, stats: "AttackStats") -> None:
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
            progress_bar = "█" * min(50, int(stats.packets_sent / 10)) + "░" * (
                50 - min(50, int(stats.packets_sent / 10))
            )
            stats_text += (
                f"[green]{progress_bar}[/green] {stats.packets_sent:,} packets"
            )
        else:
            stats_text += "[red]No packets sent yet[/red]"

        if stats.errors:
            stats_text += "\n\n[red]Recent Errors:[/red]\n"
            for error in stats.errors[-3:]:  # Show last 3 errors
                stats_text += f"• {error}\n"

        self.layout["stats"].update(
            Panel(stats_text, title="Live Statistics", style="blue")
        )

    def get_layout(self) -> Layout:
        """Get the current layout."""
        return self.layout
