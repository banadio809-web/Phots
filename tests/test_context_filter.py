import json
import tempfile
import unittest
from pathlib import Path

import context_filter


class ContextFilterTests(unittest.TestCase):
    def test_annotates_nearby_controls_but_does_not_suppress_live_sink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "plugin.php").write_text(
                "<?php\nif (!current_user_can('manage_options')) { return; }\n"
                "echo $_GET['value'];\n",
                encoding="utf-8",
            )
            suppressed, kept = context_filter.apply_context_filter(
                [{"file": "plugin.php", "line": 3, "class_hint": "stored_xss"}], root
            )

        self.assertEqual(suppressed, [])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["context_verdict"], "needs_review")
        self.assertTrue(kept[0]["context_flags"]["access_control"])

    def test_suppresses_only_a_finding_on_a_comment_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "plugin.php").write_text("<?php\n// echo $_GET['x'];\necho $_GET['x'];\n", encoding="utf-8")
            suppressed, kept = context_filter.apply_context_filter(
                [
                    {"file": "plugin.php", "line": 2, "class_hint": "stored_xss"},
                    {"file": "plugin.php", "line": 3, "class_hint": "stored_xss"},
                ],
                root,
            )

        self.assertEqual([item["line"] for item in suppressed], [2])
        self.assertEqual([item["line"] for item in kept], [3])

    def test_does_not_read_source_paths_outside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            findings = [{"file": "..\\secret.php", "line": 1, "class_hint": "stored_xss"}]
            suppressed, kept = context_filter.apply_context_filter(findings, root)

        self.assertEqual(suppressed, [])
        self.assertEqual(len(kept), 1)
        self.assertTrue(any("outside" in reason for reason in kept[0]["suppression_reasons"]))

    def test_reviewed_clean_loader_fails_closed_for_malformed_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewed.json"
            path.write_text(json.dumps({"reviewed_clean": ["a", 1, None, "b"]}), encoding="utf-8")
            self.assertEqual(context_filter.load_reviewed_clean(path), {"a", "b"})
            path.write_text(json.dumps({"reviewed_clean": "not-a-list"}), encoding="utf-8")
            self.assertEqual(context_filter.load_reviewed_clean(path), set())

    def test_save_and_load_reviewed_clean_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "reviewed.json"
            context_filter.save_reviewed_clean(path, {"b", "a"})
            self.assertEqual(context_filter.load_reviewed_clean(path), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
