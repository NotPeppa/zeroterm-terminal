#!/usr/bin/env python3
"""Local-only release load helper checks; no listeners or remote operations."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from release_load import make_random_file, hash_file


class LoadHelpers(unittest.TestCase):
    def test_incremental_random_file_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'random.bin'
            digest = make_random_file(path, 128 * 1024)
            self.assertEqual(hash_file(path), digest)
            self.assertEqual(path.stat().st_size, 128 * 1024)
            self.assertEqual(len(digest), hashlib.sha256().digest_size * 2)


if __name__ == '__main__':
    unittest.main()
