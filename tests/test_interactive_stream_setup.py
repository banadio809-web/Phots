import unittest
from unittest import mock

import scanner


class InteractiveStreamSetupTests(unittest.TestCase):
    def test_interactive_stream_sets_context_filter_options(self):
        answers = iter(["1", "1", "", "output", "n", "n"])
        captured = {}

        def fake_stream(options):
            captured["options"] = options

        with (
            mock.patch.object(scanner.sys.stdin, "isatty", return_value=True),
            mock.patch.object(scanner.sys.stdout, "reconfigure", create=True),
            mock.patch("builtins.input", side_effect=lambda _prompt="": next(answers)),
            mock.patch.object(scanner.shutil, "which", return_value=None),
            mock.patch.object(scanner, "concurrency_recommendation", return_value=(1, 1.0, "test")),
            mock.patch.object(scanner, "stream", side_effect=fake_stream),
        ):
            result = scanner._launch_interactive()

        self.assertEqual(result, 0)
        self.assertTrue(captured["options"].context_filter)
        self.assertEqual(captured["options"].reviewed_clean, "output/reviewed_clean.json")


if __name__ == "__main__":
    unittest.main()
