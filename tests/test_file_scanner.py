import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from core.file_scanner import FileScannerThread, FileSignatureScanner


class FileScannerTests(unittest.TestCase):
    def test_finds_content_signature_across_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "sample.bin"
            file_path.write_bytes(b"prefix vir" + b"us suffix")
            scanner = FileSignatureScanner(chunk_size=4)
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

    def test_stops_scanning_when_cancelled(self):
        stop_event = threading.Event()
        stop_event.set()

        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "sample.bin"
            file_path.write_bytes(b"a" * 16)
            scanner = FileSignatureScanner(signatures=[], chunk_size=4)

            self.assertEqual(
                scanner.scan_file(str(file_path), cancel_event=stop_event),
                "Cancelled",
            )

    def test_rejects_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.bin"
            target.write_bytes(b"malware")
            link = Path(directory) / "link.bin"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable")

            status = FileSignatureScanner().scan_file(str(link))

            self.assertTrue(status.startswith("Error:"))

    def test_rejects_named_pipes_without_reading_them(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("Named pipes are unavailable")

        with tempfile.TemporaryDirectory() as directory:
            pipe = Path(directory) / "pipe"
            os.mkfifo(pipe)

            self.assertEqual(
                FileSignatureScanner(signatures=[]).scan_file(str(pipe)),
                "Error: Not a regular file",
            )

    def test_walks_directory_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = FileScannerThread(directory)
            walk_result = [(directory, [], ["one.bin", "two.bin"])]

            with patch("core.file_scanner.os.walk", return_value=iter(walk_result)) as walk:
                with patch.object(scanner, "scan_file", return_value="Clean"):
                    scanner.run()

            walk.assert_called_once_with(
                directory,
                onerror=FileScannerThread._log_walk_error,
            )
            self.assertEqual(len(scanner.results), 2)


if __name__ == "__main__":
    unittest.main()
