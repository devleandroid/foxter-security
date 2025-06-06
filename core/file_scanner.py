import os
import hashlib
import logging
from PyQt5.QtCore import QThread, pyqtSignal
from infra.signature_db import MALICIOUS_SIGNATURES

class FileScannerThread(QThread):
    progress = pyqtSignal(int)
    batch_scanned = pyqtSignal(list)
    finished = pyqtSignal(list)

    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.results = []
        self.is_running = True

    def run(self):
        if not os.path.exists(self.directory):
            logging.error(f"Diretório inválido: {self.directory}")
            self.finished.emit([])
            return
        total_files = sum(len(files) for _, _, files in os.walk(self.directory))
        if total_files == 0:
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
                    self.results.append(result)  # Acumula todos os resultados
                    processed_files += 1
                    if len(batch) >= 10:
                        self.batch_scanned.emit(batch[:])
                        batch.clear()
                    if total_files > 0:
                        progress = int((processed_files / total_files) * 100)
                        self.progress.emit(progress)
                except Exception as e:
                    logging.error(f"Erro ao escanear {file_path}: {str(e)}")
                    result = {"path": file_path, "status": f"Error: {str(e)}"}
                    batch.append(result)
                    self.results.append(result)  # Acumula erros também
        if batch:
            self.batch_scanned.emit(batch)
        self.progress.emit(100)
        self.finished.emit(self.results)  # Emite todos os resultados
        logging.info(f"Escaneamento concluído: {self.directory}")

    def scan_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
                if file_hash in MALICIOUS_SIGNATURES:
                    return "Suspicious"
            return "Clean"
        except Exception as e:
            logging.error(f"Erro ao calcular hash {file_path}: {str(e)}")
            return f"Error: {str(e)}"

    def stop(self):
        self.is_running = False