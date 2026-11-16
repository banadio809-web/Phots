import unittest
from pathlib import Path
from unittest import mock

import scanner


class ResourceLimitTests(unittest.TestCase):
    def test_memory_recommendation_respects_cgroup_headroom(self):
        with (
            mock.patch.object(scanner.os, "name", "nt"),
            mock.patch.object(scanner.ctypes, "windll", create=True) as windll,
            mock.patch.object(scanner, "_cgroup_memory_available_bytes", return_value=1024**3),
        ):
            windll.kernel32.GlobalMemoryStatusEx.side_effect = lambda state: setattr(
                state._obj, "ullAvailPhys", 4 * 1024**3) or 1
            self.assertEqual(scanner.memory_available_bytes(), 1024**3)

    def test_cpu_count_respects_cgroup_quota(self):
        original_read_text = Path.read_text

        def read_quota(path, *args, **kwargs):
            if path == Path("/sys/fs/cgroup/cpu.max"):
                return "150000 100000"
            if path == Path("/sys/fs/cgroup/memory.max"):
                return "max"
            return original_read_text(path, *args, **kwargs)

        with (
            mock.patch.object(scanner.os, "cpu_count", return_value=8),
            mock.patch.object(Path, "read_text", autospec=True, side_effect=read_quota),
        ):
            self.assertEqual(scanner.available_cpu_count(), 1)

    def test_recommendation_stays_inside_container_cpu_and_memory_budget(self):
        with (
            mock.patch.object(scanner, "memory_available_bytes", return_value=3 * 1024**3),
            mock.patch.object(scanner, "available_cpu_count", return_value=2),
        ):
            workers, _, _ = scanner.concurrency_recommendation(10, semgrep_enabled=True)
        self.assertEqual(workers, 1)


if __name__ == "__main__":
    unittest.main()
