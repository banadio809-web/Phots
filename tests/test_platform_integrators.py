import json
import tempfile
import unittest
from pathlib import Path

from patchstack_integrator import PatchstackIntegrator
from wordfence_integrator import WordfenceIntegrator


class WordfenceIntegratorTests(unittest.TestCase):
    def test_imports_json_export_maps_severity_and_enhances_explicit_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.json"
            path.write_text(json.dumps({"rules": [{
                "id": "wf-42", "title": "SQL injection", "severity": "critical",
                "category": "sql_injection", "description": "User-controlled query",
                "pattern": "unsafe_query",
            }]}), encoding="utf-8")
            integrator = WordfenceIntegrator(path)

        result = integrator.enhance_finding({"wordfence_rule_id": "wf-42", "signal": "unsafe query"})
        self.assertEqual(len(integrator.rules), 1)
        self.assertEqual(result["wordfence"]["severity_score"], 9)
        self.assertEqual(result["class_hint"], "sql_injection")
        self.assertNotIn("wordfence", integrator.enhance_finding({"signal": "unmatched"}))

    def test_rejects_invalid_rule_regex(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text(json.dumps([{"id": "bad", "pattern": "("}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid regex"):
                WordfenceIntegrator(path)


class PatchstackIntegratorTests(unittest.TestCase):
    def test_imports_local_data_and_correlates_unique_plugin_slug(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "patchstack.json"
            path.write_text(json.dumps({"vulnerabilities": [{
                "id": "ps-7", "name": "Stored XSS", "slug": "demo-plugin",
                "severity": "high", "cve": "CVE-2024-12345",
                "affected_versions": "< 2.1", "fixed_in": "2.1",
            }]}), encoding="utf-8")
            integrator = PatchstackIntegrator(path)

        result = integrator.correlate_finding({"plugin_slug": "demo-plugin", "signal_id": "abc"})
        self.assertEqual(result["cve"], "CVE-2024-12345")
        self.assertEqual(result["patchstack"]["severity_score"], 8)
        self.assertEqual(result["patchstack"]["fixed_in"], "2.1")

    def test_invalid_cve_and_ambiguous_slug_are_not_attached(self):
        integrator = PatchstackIntegrator()
        integrator._parse([{"id": "a", "slug": "demo", "cve": "CVE-2024-XXXXX"},
                           {"id": "b", "slug": "demo", "cve": "CVE-2024-12345"}])
        result = integrator.correlate_finding({"plugin_slug": "demo"})
        self.assertNotIn("cve", result)
        self.assertNotIn("patchstack", result)
        self.assertIsNone(integrator.vulnerabilities[0].cve)


if __name__ == "__main__":
    unittest.main()
