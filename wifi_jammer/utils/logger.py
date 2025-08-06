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
from ..core.interfaces import ILogger


class RichLogger(ILogger):
    """Rich console logger implementation."""
    
    def __init__(self, level: str = "INFO", log_file: Optional[str] = None):
        self.console = Console(theme=Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
            "success": "green"
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
        """Log an error message."""
        self.logger.error(f"[red]ERROR:[/red] {message}")
    
    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.logger.warning(f"[yellow]WARNING:[/yellow] {message}")
    
    def success(self, message: str) -> None:
        """Log a success message."""
        self.logger.info(f"[green]SUCCESS:[/green] {message}")
    
    def info(self, message: str) -> None:
        """Log an info message."""
        self.logger.info(f"[cyan]INFO:[/cyan] {message}")


class SimpleLogger(ILogger):
    """Simple console logger implementation."""
    
    def __init__(self, level: str = "INFO"):
        self.level = level.upper()
        self.level_num = getattr(logging, self.level)
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level_upper = level.upper()
        if getattr(logging, level_upper) >= self.level_num:
            print(f"[{timestamp}] {level_upper}: {message}")
    
    def error(self, message: str) -> None:
        """Log an error message."""
        self.log(message, "ERROR")
    
    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.log(message, "WARNING") 