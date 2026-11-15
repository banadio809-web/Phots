import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

import scanner


class AISetupTests(unittest.TestCase):
    def test_saves_valid_settings_without_echoing_api_key(self):
        output = io.StringIO()
        with (
            mock.patch.object(scanner.sys, "stdin", mock.Mock(isatty=lambda: True)),
            mock.patch("builtins.input", side_effect=["https://ai.example/v1", "test-model"]),
            mock.patch.object(scanner.getpass, "getpass", return_value="test-secret"),
            mock.patch.object(scanner, "load_env_file"),
            mock.patch.object(scanner, "save_ai_settings", return_value=Path(".env")) as save,
            contextlib.redirect_stdout(output),
        ):
            scanner.configure_ai_interactively()

        save.assert_called_once_with("https://ai.example/v1", "test-model", "test-secret")
        self.assertNotIn("test-secret", output.getvalue())

    def test_rejects_non_https_remote_endpoint_before_saving(self):
        with (
            mock.patch.object(scanner.sys, "stdin", mock.Mock(isatty=lambda: True)),
            mock.patch("builtins.input", side_effect=["http://ai.example/v1", "test-model"]),
            mock.patch.object(scanner.getpass, "getpass", return_value=""),
            mock.patch.object(scanner, "load_env_file"),
            mock.patch.object(scanner, "save_ai_settings") as save,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(ValueError):
                scanner.configure_ai_interactively()

        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
