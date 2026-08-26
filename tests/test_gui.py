#!/usr/bin/env python3
"""
Offscreen GUI smoke test.

Constructs the PyQt6 MainWindow with dialogs stubbed out so the test never
blocks on exec(). Skipped automatically when PyQt6 (optional [gui] extra)
is not installed.
"""

import os
import sys
import unittest

from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication  # noqa: E402

    HAS_PYQT = True
except ImportError:  # pragma: no cover - depends on optional extra
    HAS_PYQT = False


@unittest.skipUnless(HAS_PYQT, "PyQt6 not installed ([gui] extra)")
class TestGuiSmoke(unittest.TestCase):
    def test_main_window_constructs_and_closes(self):
        """MainWindow builds its tabs and survives close without blocking."""
        from wifi_jammer.gui.main_window import MainWindow

        with patch("wifi_jammer.gui.main_window.QMessageBox") as mock_box:
            mock_box.return_value.exec.return_value = 0

            app = QApplication.instance() or QApplication([])
            window = MainWindow()

            self.assertIsNotNone(window.centralWidget())
            window.close()
            app.processEvents()
            mock_box.return_value.exec.assert_called()


if __name__ == "__main__":
    unittest.main()
