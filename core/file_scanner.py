import os
import hashlib
import logging
import stat
import string
import threading
from PyQt5.QtCore import QThread, pyqtSignal
from infra.signature_db import MALICIOUS_SIGNATURES


class FileSignatureScanner:
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, signatures=None, chunk_size=None):
        signatures = tuple(
            str(signature)
            for signature in (MALICIOUS_SIGNATURES if signatures is None else signatures)
        )
        self.chunk_size = self.CHUNK_SIZE if chunk_size is None else chunk_size
        self.content_signatures = tuple(
            signature.encode("utf-8").lower()
            for signature in signatures
            if not self._is_hash_signature(signature)
        )
        self.hash_signatures = frozenset(
            signature.lower()
            for signature in signatures
            if self._is_hash_signature(signature)
        )

    def scan_file(self, file_path, cancel_event=None):
        descriptor = None
        try:
            if os.path.islink(file_path):
                return "Error: Symbolic links are not scanned"
            digest = hashlib.sha256() if self.hash_signatures else None
            overlap = b""
            overlap_size = (
                max((len(signature) for signature in self.content_signatures), default=1) - 1
            )
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(file_path, flags)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return "Error: Not a regular file"
            with os.fdopen(descriptor, "rb") as f:
                descriptor = None
                while True:
                    if cancel_event and cancel_event.is_set():
                        return "Cancelled"
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    if digest:
                        digest.update(chunk)
                    if self.content_signatures:
                        content = (overlap + chunk).lower()
                        if any(signature in content for signature in self.content_signatures):
                            return "Suspicious"
                        overlap = content[-overlap_size:] if overlap_size else b""
            if digest and digest.hexdigest() in self.hash_signatures:
                return "Suspicious"
            return "Clean"
        except OSError as e:
            logging.error(f"Erro ao calcular hash {file_path}: {e}")
            return f"Error: {e}"
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _is_hash_signature(signature):
        return len(signature) == 64 and all(
            character in string.hexdigits for character in signature
        )


class FileScannerThread(QThread):
    progress = pyqtSignal(int)
    batch_scanned = pyqtSignal(list)
    finished = pyqtSignal(list)

    CHUNK_SIZE = FileSignatureScanner.CHUNK_SIZE
    BATCH_SIZE = 100

    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.results = []
        self.is_running = True
        self._stop_event = threading.Event()
        self.scanner = FileSignatureScanner(chunk_size=self.CHUNK_SIZE)

    def run(self):
        self.results = []
        if not os.path.isdir(self.directory):
            logging.error(f"Diretório inválido: {self.directory}")
            self.finished.emit([])
            return

        processed_files = 0
        batch = []
        for root, _, files in os.walk(self.directory, onerror=self._log_walk_error):
            if not self.is_running:
                break
            for file_name in files:
                if not self.is_running:
                    break
                file_path = os.path.join(root, file_name)
                try:
                    status = self.scan_file(file_path)
                    result = {"path": file_path, "status": status}
                    batch.append(result)
                    self.results.append(result)
                    processed_files += 1
                    if len(batch) >= self.BATCH_SIZE:
                        self.batch_scanned.emit(batch[:])
                        batch.clear()
                    if processed_files % self.BATCH_SIZE == 0:
                        self.progress.emit(processed_files)
                except Exception as e:
                    logging.error(f"Erro ao escanear {file_path}: {str(e)}")
                    result = {"path": file_path, "status": f"Error: {str(e)}"}
                    batch.append(result)
                    self.results.append(result)
        if batch:
            self.batch_scanned.emit(batch)
        self.progress.emit(processed_files)
        self.finished.emit(self.results)
        logging.info(f"Escaneamento concluído: {self.directory}")

    def scan_file(self, file_path):
        return self.scanner.scan_file(file_path, cancel_event=self._stop_event)

    def stop(self):
        self.is_running = False
        self._stop_event.set()

    @staticmethod
    def _log_walk_error(error):
        logging.warning(f"Erro ao percorrer diretório durante o escaneamento: {error}")
