"""
Logger implementation for WiFi jamming tool.
"""

import logging
import sys
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from wifi_jammer.core.interfaces import ILogger


class RichLogger(ILogger):
    """Rich console logger implementation."""
    
    def __init__(self, level: str = "INFO", log_file: Optional[str] = None, quiet: bool = False):
        self.quiet = quiet
        self.console = Console(theme=Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
            "success": "green",
            "debug": "dim"
        }))
        
        self.logger = logging.getLogger("wifi_jammer")
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Rich handler for console output
        rich_handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=False,
            markup=True
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(rich_handler)
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            self.logger.addHandler(file_handler)
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message with specified level."""
        level_map = {
            "DEBUG": self.logger.debug,
            "INFO": self.logger.info,
            "WARNING": self.logger.warning,
            "ERROR": self.logger.error,
            "CRITICAL": self.logger.critical
        }
        level_map.get(level.upper(), self.logger.info)(message)
    
    def error(self, message: str) -> None:
        """Log an error message with enhanced formatting."""
        if self.quiet: return
        error_text = Text(f"❌ ERROR: {message}", style="red")
        self.console.print(error_text)
    
    def warning(self, message: str) -> None:
        """Log a warning message with enhanced formatting."""
        if self.quiet: return
        warning_text = Text(f"⚠️  WARNING: {message}", style="yellow")
        self.console.print(warning_text)
    
    def success(self, message: str) -> None:
        """Log a success message with enhanced formatting."""
        if self.quiet: return
        success_text = Text(f"✅ SUCCESS: {message}", style="green")
        self.console.print(success_text)
    
    def info(self, message: str) -> None:
        """Log an info message with enhanced formatting."""
        if self.quiet: return
        info_text = Text(f"ℹ️  INFO: {message}", style="cyan")
        self.console.print(info_text)
    
    def debug(self, message: str) -> None:
        """Log a debug message."""
        debug_text = Text(f"🔍 DEBUG: {message}", style="dim")
        self.console.print(debug_text)
    
    def status(self, message: str) -> None:
        """Log a status message with special formatting."""
        if self.quiet: return
        status_text = Text(f"🔄 {message}", style="blue")
        self.console.print(status_text)
    
    def packet_sent(self, packet_num: int, target: str = None) -> None:
        """Log packet sent with target information."""
        if self.quiet: return
        target_info = f" to {target}" if target else ""
        packet_text = Text(f"📦 Packet #{packet_num:,} sent{target_info}", style="green")
        self.console.print(packet_text)
    
    def attack_started(self, attack_type: str, target: str) -> None:
        """Log attack start with details."""
        if self.quiet: return
        attack_panel = Panel(
            f"[bold green]Attack Started![/bold green]\n"
            f"Type: {attack_type}\n"
            f"Target: {target}\n"
            f"Status: [green]Running[/green]",
            title="🚀 Attack Status",
            style="green"
        )
        self.console.print(attack_panel)
    
    def attack_stopped(self, stats: dict = None) -> None:
        """Log attack stop with statistics."""
        if self.quiet: return
        if stats:
            stats_text = f"""
[bold]Attack Completed[/bold]
Packets Sent: {stats.get('packets_sent', 0):,}
Duration: {stats.get('duration', 0):.1f}s
Success Rate: {stats.get('success_rate', 0):.1f}%
"""
            stop_panel = Panel(stats_text, title="🛑 Attack Stopped", style="yellow")
            self.console.print(stop_panel)
        else:
            stop_text = Text("🛑 Attack stopped", style="yellow")
            self.console.print(stop_text) 