import os
import hashlib
import logging
import string
from PyQt5.QtCore import QThread, pyqtSignal
from infra.signature_db import MALICIOUS_SIGNATURES


class FileScannerThread(QThread):
    progress = pyqtSignal(int)
    batch_scanned = pyqtSignal(list)
    finished = pyqtSignal(list)

    CHUNK_SIZE = 1024 * 1024
    BATCH_SIZE = 100

    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.results = []
        self.is_running = True
        signatures = (str(signature) for signature in MALICIOUS_SIGNATURES)
        self.content_signatures = tuple(
            signature.encode("utf-8").lower()
            for signature in signatures
            if not self._is_hash_signature(signature)
        )
        self.hash_signatures = frozenset(
            signature.lower()
            for signature in MALICIOUS_SIGNATURES
            if self._is_hash_signature(str(signature))
        )

    def run(self):
        self.results = []
        if not os.path.isdir(self.directory):
            logging.error(f"Diretório inválido: {self.directory}")
            self.finished.emit([])
            return

        processed_files = 0
        batch = []
        for root, _, files in os.walk(self.directory):
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
        try:
            digest = hashlib.sha256() if self.hash_signatures else None
            overlap = b""
            overlap_size = (
                max((len(signature) for signature in self.content_signatures), default=1) - 1
            )
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
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
        except Exception as e:
            logging.error(f"Erro ao calcular hash {file_path}: {str(e)}")
            return f"Error: {str(e)}"

    def stop(self):
        self.is_running = False

    @staticmethod
    def _is_hash_signature(signature):
        return len(signature) == 64 and all(
            character in string.hexdigits for character in signature
        )
