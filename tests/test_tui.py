import io
from contextlib import redirect_stderr
import unittest
from types import SimpleNamespace
from unittest import mock

import scanner


class TUITests(unittest.TestCase):
    def test_no_argument_launcher_explains_terminal_requirement(self):
        terminal = mock.Mock()
        terminal.isatty.return_value = False
        error = io.StringIO()

        with mock.patch.object(scanner.sys, "stdin", terminal), redirect_stderr(error):
            result = scanner.launch_interactive()

        self.assertEqual(result, 2)
        self.assertIn("interactive launcher needs a terminal", error.getvalue())
        self.assertIn("phots --help", error.getvalue())

    def test_interactive_launcher_enables_replacement_for_legacy_console_encoding(self):
        stdout = mock.Mock()
        stdout.reconfigure = mock.Mock()
        terminal = mock.Mock()
        terminal.isatty.return_value = False
        error = io.StringIO()
        with (
            mock.patch.object(scanner.sys, "stdout", stdout),
            mock.patch.object(scanner.sys, "stdin", terminal),
            redirect_stderr(error),
        ):
            result = scanner.launch_interactive()
        self.assertEqual(result, 2)
        stdout.reconfigure.assert_called_once_with(errors="replace")

    def test_no_argument_launcher_handles_closed_terminal_input(self):
        terminal = mock.Mock()
        terminal.isatty.return_value = True
        error = io.StringIO()

        with (
            mock.patch.object(scanner.sys, "stdin", terminal),
            mock.patch("builtins.input", side_effect=EOFError),
            redirect_stderr(error),
        ):
            result = scanner.launch_interactive()

        self.assertEqual(result, 2)
        self.assertIn("No terminal input is available", error.getvalue())

    def test_dashboard_explains_controls_and_keeps_recent_leads_visible(self):
        output = io.StringIO()
        terminal = mock.Mock()
        terminal.isatty.return_value = True
        terminal.write.side_effect = output.write
        state = {
            "status": "running",
            "workers": 4,
            "active": 2,
            "queued": 3,
            "scanned": 12,
            "signal_count": 7,
            "failures": 0,
            "uptime": "30s",
            "recommended": 2,
            "max_workers": 10,
            "poll_seconds": 60,
            "semgrep_available": True,
            "recent_signal_lines": ["sample-plugin · sql_injection · src/plugin.php:12"],
        }

        with (
            mock.patch.object(scanner.sys, "stdout", terminal),
            mock.patch.object(scanner, "terminal_size", return_value=SimpleNamespace(columns=100, lines=30)),
            mock.patch.object(scanner.time, "monotonic", return_value=5),
        ):
            scanner.draw_phots_tui(state, [])

        rendered = output.getvalue()
        self.assertIn("Welcome.", rendered)
        self.assertIn("P pause/resume", rendered)
        self.assertIn("Q quit cleanly", rendered)
        self.assertIn("2/4 active", rendered)
        self.assertIn("sample-plugin · sql_injection · src/plugin.php:12", rendered)
        self.assertIn("No plugin code is executed", rendered)


if __name__ == "__main__":
    unittest.main()
