#!/usr/bin/env python3
from setuptools import setup, find_packages

# Metadata is in pyproject.toml — this file is kept for backward compatibility
setup(
    name="wifi-jammer",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.6.1",
        "psutil",
        "colorama",
        "rich",
        "click",
        "pyyaml",
        "cryptography>=45.0.6",
        "textual",
        "PyQt6>=6.6.0",
    ],
    entry_points={
        "console_scripts": [
            "wifi-jammer=wifi_jammer.cli:cli",
            "wifi-jammer-gui=wifi_jammer.gui:launch_gui",
            "wifi-jammer-tui=wifi_jammer.tui:WiFiJammerApp",
        ],
    },
)
