import unittest
from pathlib import Path

import yaml


BASE = Path(__file__).resolve().parents[1] / "deployment" / "kubernetes" / "base"


class KubernetesManifestTests(unittest.TestCase):
    def test_catalog_and_secret_references_are_provisioned(self):
        kustomization = (BASE / "kustomization.yaml").read_text(encoding="utf-8")
        self.assertIn("configMapGenerator:", kustomization)
        self.assertTrue((BASE / "catalog.json").is_file())
        documents = [yaml.safe_load(path.read_text(encoding="utf-8"))
                     for path in (BASE / "scan-job.yaml", BASE / "stream-deployment.yaml")]
        for document in documents:
            container = (document["spec"].get("template", {}).get("spec", {})
                         .get("containers", [{}])[0])
            secret_names = {item.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
                            for item in container.get("env", [])}
            self.assertIn("phots-supabase", secret_names)

    def test_stream_is_single_replica_and_has_separate_state_claim(self):
        manifest = yaml.safe_load((BASE / "stream-deployment.yaml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["spec"]["replicas"], 1)
        self.assertEqual(manifest["spec"]["strategy"]["type"], "Recreate")
        claims = {volume["persistentVolumeClaim"]["claimName"]
                  for volume in manifest["spec"]["template"]["spec"]["volumes"]
                  if "persistentVolumeClaim" in volume}
        self.assertEqual(claims, {"phots-stream-state"})
        args = manifest["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--no-tui", args)

    def test_scan_and_stream_resource_profiles_are_declared(self):
        scan = yaml.safe_load((BASE / "scan-job.yaml").read_text(encoding="utf-8"))
        stream = yaml.safe_load((BASE / "stream-deployment.yaml").read_text(encoding="utf-8"))
        scan_container = scan["spec"]["template"]["spec"]["containers"][0]
        stream_container = stream["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(scan_container["args"][scan_container["args"].index("--workers") + 1], "2")
        self.assertEqual(stream_container["args"][stream_container["args"].index("--workers") + 1], "1")
        self.assertEqual(scan_container["resources"]["requests"]["memory"], "3Gi")
        self.assertEqual(stream_container["resources"]["requests"]["memory"], "3Gi")


if __name__ == "__main__":
    unittest.main()
