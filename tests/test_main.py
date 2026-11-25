import tempfile
import unittest
from pathlib import Path

import main


class ArchiveSafetyTests(unittest.TestCase):
    def test_archive_merge_keeps_existing_and_deduplicates(self):
        merged = main.merge_archive_bridges({"bridge-a", "bridge-b"}, {"bridge-b", "bridge-c"}, {"bridge-d"})
        self.assertEqual(merged, {"bridge-a", "bridge-b", "bridge-c", "bridge-d"})

    def test_empty_archive_update_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bridges.txt"
            path.write_text("bridge-a\n", encoding="utf-8")
            updated = main.write_lines_atomic(str(path), [], preserve_existing_on_empty=True)
            self.assertFalse(updated)
            self.assertEqual(path.read_text(encoding="utf-8"), "bridge-a\n")

    def test_non_empty_archive_update_replaces_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bridges.txt"
            path.write_text("old-bridge\n", encoding="utf-8")
            updated = main.write_lines_atomic(str(path), ["new-bridge", "new-bridge"])
            self.assertTrue(updated)
            self.assertEqual(path.read_text(encoding="utf-8"), "new-bridge\n")
            self.assertFalse(Path(str(path) + ".tmp").exists())

    def test_history_retains_entries_older_than_thirty_days(self):
        history = {"old-bridge": "2020-01-01T00:00:00"}
        self.assertEqual(main.cleanup_history(history), history)

    def test_history_drops_invalid_timestamps(self):
        history = {"valid": "2026-11-25T00:00:00", "invalid": "not-a-date"}
        self.assertEqual(main.cleanup_history(history), {"valid": "2026-11-25T00:00:00"})


if __name__ == "__main__":
    unittest.main()
