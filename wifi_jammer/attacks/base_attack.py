"""
Base attack class for WiFi jamming attacks.
"""

import copy
import threading
import time
import os
import random
from abc import ABC, abstractmethod
from typing import Optional, Any, List, Callable
from dataclasses import dataclass
from scapy.packet import Packet
from scapy.sendrecv import sendp
from wifi_jammer.core.interfaces import IAttackStrategy, AttackConfig
from wifi_jammer.config import get_config_value
from wifi_jammer.utils.logger import RichLogger
from wifi_jammer.utils.validators import validate_attack_config
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from wifi_jammer.utils.platform_utils import is_macos, is_unix_like


@dataclass
class AttackStats:
    """Statistics for attack progress."""

    packets_sent: int = 0
    packets_failed: int = 0
    start_time: Optional[float] = None
    last_packet_time: Optional[float] = None
    errors: Optional[List[Any]] = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []

    @property
    def duration(self) -> float:
        """Get attack duration in seconds."""
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        """Get packets per second rate."""
        if self.duration == 0:
            return 0.0
        return self.packets_sent / self.duration

    @property
    def success_rate(self) -> float:
        """Get success rate percentage."""
        total = self.packets_sent + self.packets_failed
        if total == 0:
            return 0.0
        return (self.packets_sent / total) * 100


class BaseAttack(IAttackStrategy, ABC):
    """Base class for all attack strategies."""

    def __init__(self, logger: Optional[RichLogger] = None) -> None:
        self.logger = logger or RichLogger()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._config: Optional[AttackConfig] = None
        self._stats = AttackStats()
        self._stats_lock = threading.Lock()
        self._progress_callback: Optional[Callable[[AttackStats], None]] = None
        self._platform_interface = PlatformInterfaceFactory.create()

    @abstractmethod
    def _create_packet(self) -> Optional[Packet]:
        """Create the attack packet. Must be implemented by subclasses."""
        ...

    def execute(self, config: AttackConfig) -> bool:
        """Execute the attack with given configuration."""
        if self._running:
            self.logger.warning("Attack already running")
            return False

        # Validate configuration
        is_valid, error_msg = validate_attack_config(config)
        if not is_valid:
            self.logger.error(f"Invalid attack configuration: {error_msg}")
            return False

        # Check for root privileges before starting attack
        if is_unix_like():
            try:
                euid = os.geteuid()
                uid = os.getuid()

                # Debug: Log current privileges
                if self.logger.verbose if hasattr(self.logger, "verbose") else False:
                    self.logger.info(f"Running as EUID: {euid}, UID: {uid}")

                if euid != 0:
                    self.logger.error(
                        "⚠️  Root privileges required for packet injection!\n"
                        "   On macOS/Linux, attacks require root access to use /dev/bpf* or raw sockets.\n"
                        f"   Current EUID: {euid} (need 0)\n"
                        "   Please run with: sudo wifi-jammer attack [options]"
                    )
                    return False
                else:
                    # Verify we can actually access /dev/bpf* on macOS
                    if is_macos():
                        import glob

                        bpf_devices = glob.glob("/dev/bpf*")
                        if not bpf_devices:
                            self.logger.warning(
                                "⚠️  No /dev/bpf* devices found. This may indicate a system issue.\n"
                                "   Try: sudo kextunload -b com.apple.driver.AppleAirPort && sudo kextload -b com.apple.driver.AppleAirPort"
                            )
            except AttributeError:
                # Windows doesn't have geteuid(), skip check
                pass

        self._config = config
        self._running = True
        self._stats = AttackStats()
        self._stats.start_time = time.time()

        try:
            # Check platform-specific limitations
            if is_macos():
                # macOS has very limited monitor mode support
                monitor_success = self._set_monitor_mode(config.interface)
                if not monitor_success:
                    self.logger.warning(
                        f"⚠️  Monitor mode setup failed on {config.interface}\n"
                        "   macOS has very limited monitor mode support.\n"
                        "   Most modern Macs cannot inject packets in managed mode.\n"
                        "   You may need:\n"
                        "   - An external WiFi adapter that supports monitor mode\n"
                        "   - Or use a Linux system for packet injection\n"
                        "   Continuing anyway, but packets may not be effective..."
                    )
                else:
                    self.logger.info("✅ Monitor mode enabled (if supported)")
            else:
                # Set interface to monitor mode
                if not self._set_monitor_mode(config.interface):
                    self.logger.warning(
                        f"Failed to set monitor mode on {config.interface}, continuing anyway..."
                    )

            # Set channel if specified
            if config.channel > 0:
                channel_success = self._set_channel(config.interface, config.channel)
                if channel_success:
                    self.logger.info(f"✅ Channel set to {config.channel}")
                else:
                    self.logger.warning(
                        f"⚠️  Failed to set channel {config.channel}\n"
                        "   This may cause packets to be sent on the wrong channel.\n"
                        "   Make sure you're on the same channel as the target network."
                    )
            else:
                self.logger.warning(
                    "⚠️  No channel specified!\n"
                    "   Packets may be sent on the wrong channel.\n"
                    "   Specify --channel to match the target network's channel."
                )

            # Start attack in background thread
            self._thread = threading.Thread(target=self._attack_loop)
            self._thread.daemon = True
            self._thread.start()

            # Log attack start with enhanced formatting
            attack_type = self.__class__.__name__
            target = config.target_bssid or "Broadcast"
            self.logger.attack_started(attack_type, target)

            self.logger.info(f"Interface: {config.interface}")
            self.logger.info(f"Channel: {config.channel}")
            self.logger.info(
                f"Packet count: {'Unlimited' if config.count == 0 else config.count}"
            )
            self.logger.info(f"Delay: {config.delay}s")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start attack: {e}")
            self._running = False
            return False

    def stop(self) -> None:
        """Stop the attack."""
        if not self._running:
            return

        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

        self._log_final_stats()

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the attack to complete."""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        """Check if attack is running."""
        return self._running

    def get_stats(self) -> AttackStats:
        """Get a consistent snapshot of current attack statistics."""
        with self._stats_lock:
            return copy.deepcopy(self._stats)

    def set_progress_callback(self, callback: Callable[[AttackStats], None]) -> None:
        """Set progress callback function."""
        self._progress_callback = callback

    def _attack_loop(self) -> None:
        """Main attack loop."""
        packet_count = 0
        last_progress_time = time.time()
        progress_interval = 5.0  # Log progress every 5 seconds
        retry_count = 0
        max_retries = 5

        try:
            while self._running:
                try:
                    # Create and send packet
                    packet = self._create_packet()

                    if packet:
                        try:
                            # Send packet
                            # Note: On macOS, sendp may succeed but packets may not actually be transmitted
                            sendp(
                                packet,
                                iface=self._config.interface if self._config else "",
                                verbose=False,
                            )

                            self._stats.packets_sent += 1
                            self._stats.last_packet_time = time.time()
                            packet_count += 1
                            retry_count = 0  # Reset retry count on success

                            # Log warning on macOS after first successful packet
                            if packet_count == 1 and is_macos():
                                self.logger.warning(
                                    "ℹ️  macOS Packet Injection Notice:\n"
                                    "   Packets are being sent, but on macOS they may not be effective if:\n"
                                    "   - Interface is in managed mode (connected to a network)\n"
                                    "   - Monitor mode is not properly supported\n"
                                    "   - You're using the built-in WiFi adapter (limited support)\n"
                                    "   If you see no effect, try:\n"
                                    "   1. Disconnect from all WiFi networks\n"
                                    "   2. Use an external USB WiFi adapter with monitor mode support\n"
                                    "   3. Or use a Linux system for better compatibility"
                                )

                        except (OSError, PermissionError, RuntimeError) as e:
                            error_str = str(e)

                            # Detect permission errors and provide helpful messages
                            if (
                                "Permission denied" in error_str
                                or "bpf" in error_str.lower()
                            ):
                                error_msg = (
                                    "⚠️  Permission denied: Root privileges required for packet injection!\n"
                                    "   On macOS, this requires access to /dev/bpf* devices.\n"
                                    "   Please run with: sudo wifi-jammer attack [options]"
                                )
                                self.logger.error(error_msg)
                                self._stats.packets_failed += 1
                                if self._stats.errors is not None:
                                    self._stats.errors.append(
                                        "Permission denied: Root required"
                                    )

                                # Stop immediately on permission errors
                                retry_count = max_retries
                            else:
                                error_msg = f"Send error: {e}"
                                self.logger.error(error_msg)
                                self._stats.packets_failed += 1
                                if self._stats.errors is not None:
                                    self._stats.errors.append(error_msg)
                                retry_count += 1

                            if retry_count >= max_retries:
                                if (
                                    "Permission denied" not in error_str
                                    and "bpf" not in error_str.lower()
                                ):
                                    self.logger.error(
                                        "Too many consecutive send failures, stopping attack"
                                    )
                                break
                            time.sleep(1)
                            continue

                        # Call progress callback if set
                        if self._progress_callback:
                            try:
                                self._progress_callback(self._stats)
                            except (AttributeError, TypeError, ValueError):
                                pass  # Silent failure for callback

                        # Log progress periodically
                        current_time = time.time()
                        if current_time - last_progress_time >= progress_interval:
                            self._log_progress()
                            last_progress_time = current_time

                        # Check if we've reached the count limit
                        if self._config is not None and (
                            self._config.count > 0
                            and packet_count >= self._config.count
                        ):
                            self.logger.info(
                                f"Reached packet limit ({self._config.count})"
                            )
                            break
                    else:
                        self.logger.warning("Failed to create packet")
                        self._stats.packets_failed += 1

                    # Delay between packets, honoring the configured rate ceiling
                    # (ToolConfig.rate_limit_enabled / max_packets_per_second)
                    requested = self._config.delay if self._config else 0.1
                    time.sleep(self._effective_delay(requested))

                except (KeyboardInterrupt, SystemExit):
                    # Allow clean exit on interrupt
                    raise
                except (OSError, RuntimeError, ValueError) as e:
                    error_msg = f"Error in attack loop: {e}"
                    self.logger.error(error_msg)
                    self._stats.packets_failed += 1
                    if self._stats.errors is not None:
                        self._stats.errors.append(error_msg)
                    time.sleep(1)
        finally:
            # Ensure running state is reset and cleanup
            self._running = False
            if self._config and self._config.interface:
                # Attempt to restore interface state if needed
                try:
                    # Note: We don't restore monitor mode here as it may be intentional
                    # The user should manage interface state themselves
                    pass
                except (OSError, ValueError, AttributeError):
                    pass

    def _log_progress(self) -> None:
        """Log current attack progress."""
        with self._stats_lock:
            stats = copy.deepcopy(self._stats)
        duration = stats.duration

        if duration > 0:
            pps = stats.packets_per_second
            success_rate = stats.success_rate

            self.logger.status(
                f"Progress: {stats.packets_sent:,} packets sent, "
                f"{pps:.1f} pps, {success_rate:.1f}% success rate, "
                f"{duration:.1f}s elapsed"
            )

    def _log_final_stats(self) -> None:
        """Log final attack statistics."""
        with self._stats_lock:
            stats = copy.deepcopy(self._stats)
        duration = stats.duration

        if duration > 0:
            pps = stats.packets_per_second
            success_rate = stats.success_rate

            self.logger.success(
                f"Attack completed: {stats.packets_sent:,} packets sent, "
                f"{stats.packets_failed:,} failed, {pps:.1f} pps average, "
                f"{success_rate:.1f}% success rate, {duration:.1f}s total"
            )

            if stats.errors:
                self.logger.warning(
                    f"Encountered {len(stats.errors)} errors during attack"
                )

    def _set_monitor_mode(self, interface: str) -> bool:
        """Set interface to monitor mode."""
        return self._platform_interface.set_monitor_mode(interface)

    def _set_channel(self, interface: str, channel: int) -> bool:
        """Set interface channel."""
        return self._platform_interface.set_channel(interface, channel)

    def _effective_delay(self, requested_delay: float) -> float:
        """Delay actually slept between packets after applying the configured
        packet-rate ceiling from ToolConfig (rate_limit_enabled,
        max_packets_per_second)."""
        if not get_config_value("rate_limit_enabled", True):
            return requested_delay
        try:
            max_pps = int(get_config_value("max_packets_per_second", 1000) or 1000)
        except (TypeError, ValueError):
            max_pps = 1000
        if max_pps <= 0:
            return requested_delay
        return max(requested_delay, 1.0 / max_pps)

    def _get_random_mac(self) -> str:
        """Generate a random MAC address."""
        return f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"

    def _get_source_mac(self) -> str:
        """Get source MAC address."""
        if self._config and self._config.source_mac:
            return self._config.source_mac
        return self._get_random_mac()
