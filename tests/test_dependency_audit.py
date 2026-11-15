import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scanner


class DependencyAuditTests(unittest.TestCase):
    def test_inventory_skips_dependency_and_output_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            for relative in (
                "composer.json",
                "composer.lock",
                "frontend/package.json",
                "frontend/package-lock.json",
                "node_modules/example/package.json",
                "vendor/example/composer.json",
                "output/package.json",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")

            manifests = scanner.discover_dependency_manifests(root, output)

        self.assertEqual(
            [item["path"] for item in manifests],
            ["composer.json", "composer.lock", "frontend/package-lock.json",
             "frontend/package.json"],
        )

    def test_runs_only_installed_audit_tools_and_saves_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "composer.json").write_text("{}", encoding="utf-8")
            (root / "composer.lock").write_text("{}", encoding="utf-8")
            frontend = root / "frontend"
            frontend.mkdir()
            (frontend / "package.json").write_text("{}", encoding="utf-8")
            (frontend / "package-lock.json").write_text("{}", encoding="utf-8")
            output = root / "output"

            def which(name):
                return None if name == "composer" else "npm"

            completed = scanner.subprocess.CompletedProcess(
                args=["npm", "audit", "--json"],
                returncode=0,
                stdout='{"advisories":{}}',
                stderr="",
            )
            with (
                mock.patch.object(scanner.shutil, "which", side_effect=which),
                mock.patch.object(scanner.subprocess, "run", return_value=completed) as run,
            ):
                manifests, executables, results = scanner.run_dependency_audits(root, output, 30)

            self.assertEqual(len(manifests), 4)
            self.assertIsNone(executables["composer"])
            self.assertTrue(executables["npm"])
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs["cwd"], frontend)
            self.assertEqual(
                [(item["ecosystem"], item["status"]) for item in results],
                [("composer", "not_installed"), ("npm", "completed")],
            )
            artifact = output / results[1]["output"]
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8")), {"advisories": {}})


if __name__ == "__main__":
    unittest.main()
