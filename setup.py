#!/usr/bin/env python3
from setuptools import setup, find_packages
import platform

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Add macOS-specific dependencies
if platform.system() == "Darwin":
    requirements.append("pyobjc-framework-CoreWLAN>=10.0")

setup(
    name="wifi-jammer",
    version="2.0.0",
    author="Paijo",
    description="Advanced WiFi jamming tool with deauth, flood, channel hopping, PMKID capture, evil twin, and netcut attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'flake8>=6.0.0',
            'black>=23.0.0',
            'isort>=5.12.0',
        ],
        'crypto': [
            'cryptography>=45.0.6',
        ]
    },
    entry_points={
        "console_scripts": [
            "wifi-jammer=wifi_jammer.cli:main",
            "wifi-jammer-gui=wifi_jammer.gui:launch_gui",
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 