import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.file_scanner import FileScannerThread


class FileScannerTests(unittest.TestCase):
    def test_finds_content_signature_across_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "sample.bin"
            file_path.write_bytes(b"prefix vir" + b"us suffix")
            scanner = FileScannerThread(directory)

            with patch.object(FileScannerThread, "CHUNK_SIZE", 4):
                self.assertEqual(scanner.scan_file(str(file_path)), "Suspicious")

    def test_matches_sha256_signatures(self):
        content = b"known sample"
        signature = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "sample.bin"
            file_path.write_bytes(content)
            with patch("core.file_scanner.MALICIOUS_SIGNATURES", [signature]):
                scanner = FileScannerThread(directory)

            self.assertEqual(scanner.scan_file(str(file_path)), "Suspicious")

    def test_walks_directory_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = FileScannerThread(directory)
            walk_result = [(directory, [], ["one.bin", "two.bin"])]

            with patch("core.file_scanner.os.walk", return_value=iter(walk_result)) as walk:
                with patch.object(scanner, "scan_file", return_value="Clean"):
                    scanner.run()

            walk.assert_called_once_with(directory)
            self.assertEqual(len(scanner.results), 2)


if __name__ == "__main__":
    unittest.main()
