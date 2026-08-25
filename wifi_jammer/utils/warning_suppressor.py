"""
Warning suppression utilities for the WiFi jamming tool.

Suppression is scoped to scapy's own modules/loggers only. Blanket global
ignores (all DeprecationWarnings, PYTHONWARNINGS=ignore, etc.) previously
hid real issues everywhere else in the process.
"""

import logging
import warnings


class WarningSuppressor:
    """Scoped suppression helpers for third-party noise."""

    @staticmethod
    def suppress_scapy_warnings() -> None:
        """Suppress warnings originating from scapy modules only."""
        warnings.filterwarnings("ignore", module=r"scapy(\.|$)")

    @staticmethod
    def suppress_logging_warnings() -> None:
        """Silence scapy loggers below ERROR."""
        for name in list(logging.Logger.manager.loggerDict) + ["scapy"]:
            if "scapy" in name.lower():
                logging.getLogger(name).setLevel(logging.ERROR)


def setup_warning_suppression() -> None:
    """Apply scoped suppression (safe to call multiple times)."""
    WarningSuppressor.suppress_scapy_warnings()
    WarningSuppressor.suppress_logging_warnings()
