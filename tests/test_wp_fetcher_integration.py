import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import scanner
import wp_fetcher


def plugin_archive(stable_tag="1.2.3", payload="small"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("demo/readme.txt", f"Stable tag: {stable_tag}\n")
        zipped.writestr(
            "demo/demo.php",
            f"<?php\nPlugin Name: Demo\nVersion: {stable_tag}\n{payload}\n",
        )
    return archive.getvalue()


class _Response:
    def __init__(self, content, status):
        self.content = io.BytesIO(content)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.content.read(size)

    def getcode(self):
        return self.status


class WPFetcherIntegrationTests(unittest.TestCase):
    def test_scanner_uses_resumable_fetch_and_verified_version_cache(self):
        payload = plugin_archive()
        plugin = {
            "slug": "demo",
            "version": "1.2.3",
            "download_link": "https://downloads.wordpress.org/plugin/demo.1.2.3.zip",
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"

            def fetch(_url, destination, config):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                self.assertEqual(config.max_download_mb, 100)
                self.assertEqual(config.max_uncompressed_mb, 500)
                self.assertEqual(config.retries, 2)
                return destination, len(payload)

            with mock.patch.object(wp_fetcher, "download_plugin", side_effect=fetch) as downloader:
                slug, version, path, cached, verification = scanner.download_one(plugin, root)
                self.assertEqual((slug, version), ("demo", "1.2.3"))
                self.assertFalse(cached)
                self.assertEqual(verification["version_verified"], "1.2.3")
                self.assertTrue((path / "demo" / "demo.php").is_file())
                self.assertFalse((root / ".downloads" / "demo" / "1.2.3.zip").exists())

                _, _, cached_path, cached, cached_verification = scanner.download_one(plugin, root)

            self.assertTrue(cached)
            self.assertEqual(cached_path, path)
            self.assertEqual(cached_verification["version_verified"], "1.2.3")
            self.assertEqual(downloader.call_count, 1)
            marker = json.loads((path / ".complete").read_text(encoding="utf-8"))
            self.assertEqual(marker["version_api"], "1.2.3")
            self.assertEqual(marker["verification"]["version_source"], "stable_tag")

    def test_archive_version_mismatch_is_returned_for_scan_metadata(self):
        payload = plugin_archive(stable_tag="1.2.4")
        plugin = {
            "slug": "demo",
            "version": "1.2.3",
            "download_link": "https://downloads.wordpress.org/plugin/demo.1.2.3.zip",
        }

        with tempfile.TemporaryDirectory() as temporary:
            def fetch(_url, destination, _config):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                return destination, len(payload)

            with mock.patch.object(wp_fetcher, "download_plugin", side_effect=fetch):
                _, _, _, _, verification = scanner.download_one(plugin, Path(temporary))

        self.assertTrue(verification["drift"])
        self.assertEqual(verification["version_api"], "1.2.3")
        self.assertEqual(verification["version_verified"], "1.2.4")

    def test_scanning_labels_findings_with_the_verified_archive_version(self):
        plugin = {"slug": "demo", "version": "1.2.3"}
        verification = {
            "version_api": "1.2.3",
            "version_verified": "1.2.4",
            "version_source": "stable_tag",
            "drift": True,
        }
        findings = [{"version": "1.2.4"}]
        scan_result = ("demo", findings, False, None, "fingerprint")

        with (
            mock.patch.object(
                scanner, "download_one",
                return_value=("demo", "1.2.3", Path("source"), False, verification),
            ),
            mock.patch.object(scanner, "scan_source_tree", return_value=scan_result) as scan,
        ):
            result = scanner.download_and_scan(
                plugin, Path("source"), 100, 10, 30, False
            )

        self.assertEqual(scan.call_args.args[0]["version"], "1.2.4")
        self.assertEqual(result[1][0]["version_api"], "1.2.3")
        self.assertEqual(result[1][0]["version_source"], "stable_tag")
        self.assertTrue(result[1][0]["version_drift"])

    def test_range_download_resumes_partial_zip_and_accepts_verified_416(self):
        payload = plugin_archive()
        split = len(payload) // 2
        url = "https://downloads.wordpress.org/plugin/demo.1.2.3.zip"

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "demo.zip"
            destination.write_bytes(payload[:split])
            requests = []

            def urlopen(request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    self.assertEqual(timeout, 5)
                    self.assertEqual(request.get_header("Range"), f"bytes={split}-")
                    return _Response(payload[split:], 206)
                self.assertEqual(timeout, 30)
                self.assertEqual(
                    request.get_header("Range"),
                    f"bytes={len(payload)}-{len(payload)}",
                )
                return _Response(b"", 416)

            with mock.patch.object(wp_fetcher.urllib.request, "urlopen", side_effect=urlopen):
                result, byte_count = wp_fetcher.download_plugin(
                    url,
                    destination,
                    wp_fetcher.FetcherConfig(
                        staging=Path(temporary),
                        retries=0,
                        timeout_secs=5,
                        max_download_mb=1,
                    ),
                )
            result_bytes = result.read_bytes()

        self.assertEqual(result_bytes, payload)
        self.assertEqual(byte_count, len(payload))
        self.assertEqual(len(requests), 2)

    def test_compressed_download_limit_fails_without_repeated_attempts(self):
        url = "https://downloads.wordpress.org/plugin/demo.1.2.3.zip"
        response = _Response(b"A" * (1024 * 1024 + 1), 200)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "demo.zip"
            with mock.patch.object(
                wp_fetcher.urllib.request, "urlopen", return_value=response
            ) as urlopen:
                with self.assertRaises(wp_fetcher.FetcherPolicyError):
                    wp_fetcher.download_plugin(
                        url,
                        destination,
                        wp_fetcher.FetcherConfig(
                            staging=Path(temporary),
                            retries=3,
                            max_download_mb=1,
                        ),
                    )

        self.assertEqual(urlopen.call_count, 1)
        self.assertFalse(destination.exists())

    def test_extraction_rejects_escape_before_writing(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("../outside.php", "bad")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive_path = directory / "input.zip"
            archive_path.write_bytes(archive.getvalue())
            destination = directory / "extract"
            config = wp_fetcher.FetcherConfig(max_uncompressed_mb=1)
            with self.assertRaises(wp_fetcher.FetcherPolicyError):
                wp_fetcher.extract_plugin_zip(
                    archive_path,
                    destination,
                    config,
                )
            self.assertFalse(destination.exists())

    def test_extraction_rejects_expansion_before_writing(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("demo/large.php", "A" * (1024 * 1024 + 1))

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive_path = directory / "input.zip"
            archive_path.write_bytes(archive.getvalue())
            destination = directory / "extract"

            with self.assertRaises(wp_fetcher.FetcherPolicyError):
                wp_fetcher.extract_plugin_zip(
                    archive_path,
                    destination,
                    wp_fetcher.FetcherConfig(max_uncompressed_mb=1),
                )
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
