import tempfile
import unittest
from pathlib import Path

import scanner


def finding(slug, class_hint):
    return {
        "plugin_slug": slug,
        "signal_id": slug,
        "class_hint": class_hint,
        "confidence": "high",
        "engine": "semgrep",
        "file": "plugin.php",
        "line": 12,
        "excerpt": "source excerpt",
        "scope_decision": {"decision": "REVIEW", "reasons": []},
    }


class ReportPriorityTests(unittest.TestCase):
    def test_priority_uses_potential_impact_class_and_keeps_unknowns_unclassified(self):
        self.assertEqual(scanner.review_priority(
            finding("execution", "remote_code_execution"))["code"], "P1")
        self.assertEqual(scanner.review_priority(
            finding("sql", "sql_injection"))["code"], "P2")
        self.assertEqual(scanner.review_priority(
            finding("xss", "xss_output"))["code"], "P2")
        self.assertEqual(scanner.review_priority(
            finding("path", "directory_traversal"))["code"], "P3")
        self.assertEqual(scanner.review_priority(
            finding("auth", "authorization_bypass"))["code"], "P3")
        self.assertEqual(scanner.review_priority(
            finding("unknown", None))["code"], "UNCLASSIFIED")

    def test_markdown_and_html_reports_include_priority_counts_and_lead_labels(self):
        records = [
            finding("execution", "remote_code_execution"),
            finding("sql", "sql_injection"),
            finding("path", "directory_traversal"),
            finding("unknown", None),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            scanner.write_human_report(output, [], records, [], 0, 0, 1.0)
            markdown = (output / "report.md").read_text(encoding="utf-8")
            page = (output / "report.html").read_text(encoding="utf-8")

        self.assertIn("P1 — highest review priority:** 1", markdown)
        self.assertIn("P2 — high review priority:** 1", markdown)
        self.assertIn("P3 — standard review priority:** 1", markdown)
        self.assertIn("Unclassified — priority not assigned:** 1", markdown)
        self.assertIn("## Leads by vulnerability class", markdown)
        self.assertIn("SQL injection:** 1", markdown)
        self.assertIn("Suggested review priority:", markdown)
        self.assertLess(markdown.index("## P1 — highest review priority"),
                        markdown.index("## P2 — high review priority"))
        self.assertLess(markdown.index("## P2 — high review priority"),
                        markdown.index("## P3 — standard review priority"))
        self.assertIn("P1 — highest review priority", page)
        self.assertIn("Leads by vulnerability class", page)
        self.assertIn("class-based triage aids, not CVSS scores", page)
        self.assertEqual([item["review_priority"] for item in records],
                         ["P1", "P2", "P3", "UNCLASSIFIED"])


if __name__ == "__main__":
    unittest.main()
