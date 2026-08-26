#!/usr/bin/env python3
"""
TUI tests using Textual's Pilot harness.

Covers app composition, interface selection, screen composition, and the
attack start/stop wiring — all against mocked scanner/factory so nothing
touches real hardware.
"""

import os
import sys
import unittest

from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from textual.widgets import DataTable, Input, Label  # noqa: E402

from wifi_jammer.core.interfaces import NetworkInfo  # noqa: E402


def make_iface(name="wlan0"):
    iface = Mock()
    iface.name = name
    iface.status = "Available"
    return iface


class StubAttack:
    """Minimal IAttackStrategy double for UI wiring tests."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self._callback = None
        self._polled = 0

    def execute(self, config):
        self.started = True
        return True

    def stop(self):
        self.stopped = True

    def is_running(self):
        self._polled += 1
        return self._polled < 2

    def join(self, timeout=None):
        pass

    def get_stats(self):
        from wifi_jammer.attacks.base_attack import AttackStats

        stats = AttackStats()
        stats.start_time = 100.0
        stats.packets_sent = 5
        return stats

    def set_progress_callback(self, callback):
        self._callback = callback


def build_app():
    from wifi_jammer.tui import WiFiJammerApp

    with (
        patch("wifi_jammer.tui.PlatformInterfaceFactory") as mock_factory,
        patch("wifi_jammer.tui.platform.system", return_value="Linux"),
        patch("wifi_jammer.tui.ScapyNetworkScanner"),
    ):
        mock_factory.create.return_value.get_wireless_interfaces.return_value = [
            make_iface("wlan0")
        ]
        app = WiFiJammerApp(interface=None)
    stub_factory = Mock()
    stub_factory.create_attack.return_value = StubAttack()
    app.factory = stub_factory
    return app


async def wait_until(predicate, timeout=3.0):
    """Poll a condition set by a worker thread (execute runs off-loop)."""
    import asyncio
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return False



class TestWiFiJammerTUI(unittest.IsolatedAsyncioTestCase):
    async def test_app_auto_selects_first_interface(self):
        app = build_app()
        async with app.run_test():
            self.assertEqual(app.interface, "wlan0")

    async def test_welcome_label_renders_interface(self):
        app = build_app()
        async with app.run_test():
            label = app.screen.query_one("#welcome_container Label", Label)
            self.assertIn("wlan0", str(label.render()))

    async def test_show_attack_config_pushes_config_screen(self):
        from wifi_jammer.tui_screens import AttackConfigScreen

        app = build_app()
        async with app.run_test() as pilot:
            app.show_attack_config(
                NetworkInfo("Net", "00:11:22:33:44:55", 6, -50, "WPA2")
            )
            await pilot.pause()
            self.assertIsInstance(app.screen, AttackConfigScreen)
            delay_input = app.screen.query_one("#delay_input", Input)
            self.assertEqual(delay_input.value, "0.1")

    async def test_start_attack_from_config_creates_and_runs_attack(self):
        from wifi_jammer.tui_screens import AttackScreen

        app = build_app()
        async with app.run_test() as pilot:
            app.show_attack_config(
                NetworkInfo("Net", "00:11:22:33:44:55", 6, -50, "WPA2")
            )
            await pilot.pause()

            # Move cursor to first row == first enum member
            table = app.screen.query_one("#attack_type_table", DataTable)
            table.move_cursor(row=0, column=0)
            app._start_attack_from_config()
            await pilot.pause()

            self.assertIsInstance(app.screen, AttackScreen)
            attack = app.factory.create_attack.return_value
            self.assertTrue(await wait_until(lambda: attack.started))
            self.assertEqual(attack._callback, app.update_stats)

    async def test_stop_button_stops_attack_and_pops_screen(self):
        app = build_app()
        async with app.run_test() as pilot:
            app.show_attack_config(
                NetworkInfo("Net", "00:11:22:33:44:55", 6, -50, "WPA2")
            )
            await pilot.pause()
            table = app.screen.query_one("#attack_type_table", DataTable)
            table.move_cursor(row=0, column=0)
            app._start_attack_from_config()
            await pilot.pause()

            await pilot.click("#stop_attack")
            await pilot.pause()

            attack = app.factory.create_attack.return_value
            self.assertTrue(await wait_until(lambda: attack.stopped))

    async def test_stats_update_renders_on_attack_screen(self):
        from wifi_jammer.tui_screens import AttackScreen

        app = build_app()
        async with app.run_test() as pilot:
            app.push_screen(AttackScreen())
            await pilot.pause()
            app._update_ui_stats(app.factory.create_attack.return_value.get_stats())
            await pilot.pause()
            packets_label = app.screen.query_one("#packets_sent", Label)
            self.assertIn("5", str(packets_label.render()))


if __name__ == "__main__":
    unittest.main()
