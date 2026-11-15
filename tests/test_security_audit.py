import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import scanner


class LocalSecurityAuditTests(unittest.TestCase):
    def test_inventory_lists_security_surfaces_without_copying_secret_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "plugin.php"
            source.write_text(
                "\n".join([
                    "<?php",
                    "register_rest_route('demo/v1', '/item', $args);",
                    "add_action('wp_ajax_nopriv_demo', 'demo_handler');",
                    "current_user_can('manage_options');",
                    "check_ajax_referer('demo_nonce');",
                    "$wpdb->query($_POST['sql']);",
                    "move_uploaded_file($_FILES['upload']['tmp_name'], $path);",
                    "unserialize($_POST['state']);",
                    "update_option($_POST['name'], $_POST['value']);",
                    '$api_key = "private-token-123456";',
                ]),
                encoding="utf-8",
            )
            (root / ".env").write_text(
                "API_TOKEN=plain-private-token-123456\n",
                encoding="utf-8",
            )
            output = root / "output"
            (output / "generated.php").parent.mkdir(parents=True)
            (output / "generated.php").write_text("echo 'generated';", encoding="utf-8")

            inventory, source_files = scanner.inventory_local_project(root, output)

        self.assertEqual(source_files, [".env", "plugin.php"])
        targets = inventory["review_targets"]
        kinds = {item["kind"] for item in targets}
        self.assertTrue({
            "rest_route", "ajax_handler", "capability_check", "nonce_check",
            "wpdb_access", "upload_operation", "deserialize_operation",
            "state_change", "hardcoded_secret_candidate",
        }.issubset(kinds))
        self.assertNotIn("private-token-123456", json.dumps(inventory))
        self.assertNotIn("plain-private-token-123456", json.dumps(inventory))
        self.assertTrue(any(
            item["path"] == ".env" and item["kind"] == "hardcoded_secret_candidate"
            for item in targets
        ))

    def test_local_audit_saves_reports_and_does_not_execute_absent_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "plugin"
            root.mkdir()
            (root / "plugin.php").write_text(
                "<?php\nregister_rest_route('demo/v1', '/item', $args);\n",
                encoding="utf-8",
            )
            (root / "composer.json").write_text("{}", encoding="utf-8")
            (root / "composer.lock").write_text("{}", encoding="utf-8")
            output = Path(temporary) / "output"
            args = SimpleNamespace(
                root=str(root),
                out=str(output),
                timeout=1,
                include_dependencies=False,
                run_project_tools=False,
            )
            with (
                mock.patch.object(scanner.shutil, "which", return_value=None),
                mock.patch.object(scanner.subprocess, "run") as run,
            ):
                scanner.local_security_audit(args)

            report_dir = output / "audit"
            summary = json.loads((report_dir / "security-audit.json").read_text(encoding="utf-8"))
            inventory = json.loads((report_dir / "surface-inventory.json").read_text(encoding="utf-8"))
            file_inventory = (report_dir / "file-inventory.txt").read_text(encoding="utf-8")
            self.assertEqual(summary["scan_type"], "local_wordpress_security_audit")
            self.assertEqual(
                [item["path"] for item in summary["dependency_manifests"]],
                ["composer.json", "composer.lock"],
            )
            self.assertEqual(inventory["review_targets"][0]["kind"], "rest_route")
            self.assertTrue((report_dir / "security-audit.md").is_file())
            self.assertIn("plugin.php", file_inventory)
            self.assertNotIn("output", file_inventory)
            self.assertEqual(run.call_count, 0)
            statuses = {item["tool"]: item["status"] for item in summary["tools"]}
            self.assertEqual(statuses["semgrep"], "not_installed")
            self.assertEqual(statuses["composer/npm audit"], "disabled_by_option")
            self.assertEqual(statuses["phpcs"], "opt_in_required")
            self.assertEqual(statuses["codeql"], "manual_setup_required")


if __name__ == "__main__":
    unittest.main()
