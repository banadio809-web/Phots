import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import scanner


class StreamReliabilityTests(unittest.TestCase):
    def test_atomic_write_retries_transient_replace_lock_with_unique_temp_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "phots-memory.json"
            target.write_text("old", encoding="utf-8")
            replace = scanner.os.replace
            calls = 0

            def lock_once(source, destination):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise PermissionError("simulated OneDrive lock")
                return replace(source, destination)

            with mock.patch.object(scanner.os, "replace", side_effect=lock_once), \
                    mock.patch.object(scanner.time, "sleep"):
                scanner.atomic_write_text(target, "new")

            self.assertEqual(target.read_text(encoding="utf-8"), "new")
            self.assertEqual(calls, 2)
            self.assertEqual(list(Path(temporary).glob("*.tmp")), [])

    def test_atomic_write_cleans_temp_file_after_persistent_permission_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "phots-memory.json"
            with mock.patch.object(scanner.os, "replace", side_effect=PermissionError("locked")), \
                    mock.patch.object(scanner.time, "sleep"):
                with self.assertRaises(PermissionError):
                    scanner.atomic_write_text(target, "new", attempts=2)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temporary).glob("*.tmp")), [])

    def test_retry_backoff_only_applies_to_transient_errors(self):
        error = RuntimeError("temporary network problem")
        self.assertEqual(scanner.retry_delay_seconds(1, error), 60)
        self.assertEqual(scanner.retry_delay_seconds(2, error), 120)
        self.assertIsNone(scanner.retry_delay_seconds(3, error))
        self.assertIsNone(scanner.retry_delay_seconds(
            1, scanner.NonRetryableScanError("archive exceeds size limit")
        ))

    def test_interrupted_supabase_finalization_is_reported_without_traceback(self):
        store = mock.Mock()
        store.finish_run.side_effect = KeyboardInterrupt
        live_log = mock.Mock()
        state = {"scanned": 4, "failures": 1, "signal_count": 8}
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            scanner.finish_interrupted_stream_run(store, "run-id", state, live_log)

        store.finish_run.assert_called_once_with(
            "run-id", "failed", scanned_plugins=4, failed_plugins=1,
            signal_count=8, alert_count=0, timeout=5,
        )
        self.assertIn("may remain marked running", state["supabase_error"])
        self.assertIn("Warning:", stderr.getvalue())
        live_log.event.assert_called_once_with(
            "WARN", "supabase_stop_update_interrupted"
        )

    def test_handoff_distinguishes_configured_workers_from_active_workers(self):
        with tempfile.TemporaryDirectory() as temporary:
            handoff = Path(temporary) / "handoff.md"
            live_log = scanner.PhotsLiveLog(
                Path(temporary) / "events.log", handoff
            )
            live_log.update_handoff({
                "status": "waiting",
                "workers": 4,
                "recommended": 2,
                "active": 1,
                "queued": 0,
            })
            report = handoff.read_text(encoding="utf-8")

        self.assertIn("Configured concurrency is 4 streams", report)
        self.assertIn("currently 1 active and 0 queued", report)
        self.assertNotIn("4 streams are active", report)

    def test_dashboard_shows_configured_and_recommended_workers(self):
        output = io.StringIO()
        terminal = mock.Mock()
        terminal.isatty.return_value = True
        terminal.write.side_effect = output.write
        state = {
            "status": "running",
            "workers": 4,
            "active": 1,
            "queued": 0,
            "recommended": 2,
            "max_workers": 10,
        }

        with (
            mock.patch.object(scanner.sys, "stdout", terminal),
            mock.patch.object(
                scanner, "terminal_size",
                return_value=SimpleNamespace(columns=160, lines=30),
            ),
            mock.patch.object(scanner.time, "monotonic", return_value=5),
        ):
            scanner.draw_phots_tui(state, [])

        self.assertIn("Configured/recommended workers: 4/2", output.getvalue())


if __name__ == "__main__":
    unittest.main()
