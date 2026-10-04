import logging
import os
import queue
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.file_scanner import FileSignatureScanner


class RansomwareActivityMonitor:
    WINDOW_SECONDS = 15
    CHANGED_FILE_THRESHOLD = 25
    RENAMED_FILE_THRESHOLD = 8
    ALERT_COOLDOWN_SECONDS = 60
    SUSPICIOUS_EXTENSIONS = {
        ".encrypted",
        ".locked",
        ".crypt",
        ".crypto",
        ".ransom",
        ".enc",
    }

    def __init__(self):
        self._events = deque()
        self._last_alert = float("-inf")
        self._lock = threading.Lock()

    def record_event(self, event_type, path, destination=None, now=None):
        now = time.monotonic() if now is None else now
        normalized_path = os.path.normcase(os.path.abspath(path))
        normalized_destination = (
            os.path.normcase(os.path.abspath(destination)) if destination else None
        )

        with self._lock:
            self._events.append((now, event_type, normalized_path, normalized_destination))
            while self._events and now - self._events[0][0] > self.WINDOW_SECONDS:
                self._events.popleft()

            if event_type == "moved" and normalized_destination:
                extension = Path(normalized_destination).suffix.lower()
                if extension in self.SUSPICIOUS_EXTENSIONS:
                    return self._alert(
                        now,
                        f"Renomeação com extensão incomum detectada: {os.path.basename(destination)}",
                    )

            changed_paths = {
                event_path
                for _, kind, event_path, _ in self._events
                if kind in {"modified", "created", "moved", "deleted"}
            }
            renamed_paths = {
                event_path
                for _, kind, event_path, _ in self._events
                if kind == "moved"
            }
            if (
                len(changed_paths) >= self.CHANGED_FILE_THRESHOLD
                or len(renamed_paths) >= self.RENAMED_FILE_THRESHOLD
            ):
                return self._alert(
                    now,
                    "Muitas alterações de arquivos em pouco tempo. "
                    "Isso pode indicar ransomware; confira os processos ativos.",
                )
        return None

    def _alert(self, now, message):
        if now - self._last_alert < self.ALERT_COOLDOWN_SECONDS:
            return None
        self._last_alert = now
        logging.warning("Alerta comportamental: %s", message)
        return message


class _FileEventHandler(FileSystemEventHandler):
    def __init__(self, root, scanner, on_scan, on_warning, ignored_paths=()):
        super().__init__()
        self.root = os.path.realpath(root)
        self.scanner = scanner
        self.on_scan = on_scan
        self.on_warning = on_warning
        self.ignored_paths = tuple(os.path.realpath(path) for path in ignored_paths)
        self.activity_monitor = RansomwareActivityMonitor()
        self._lock = threading.Lock()
        self._pending = {}
        self._in_flight = set()
        self._dirty = set()
        self._stopping = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="foxter-scan")
        self._max_pending = 512
        self._last_queue_warning = 0.0

    def on_created(self, event):
        self._handle(event, "created")

    def on_modified(self, event):
        self._handle(event, "modified")

    def on_deleted(self, event):
        self._handle(event, "deleted")

    def on_moved(self, event):
        self._handle(event, "moved", getattr(event, "dest_path", None))

    def _handle(self, event, event_type, destination=None):
        if event.is_directory or self._stopping.is_set():
            return

        path = event.src_path
        warning = self.activity_monitor.record_event(event_type, path, destination)
        if warning:
            self.on_warning(warning)

        scan_path = destination if event_type == "moved" and destination else path
        self._schedule_scan(scan_path)

    def _schedule_scan(self, path):
        absolute_path = os.path.abspath(path)
        try:
            if os.path.commonpath((self.root, os.path.realpath(absolute_path))) != self.root:
                return
        except ValueError:
            return

        resolved_path = os.path.realpath(absolute_path)
        for ignored in self.ignored_paths:
            try:
                if os.path.commonpath((ignored, resolved_path)) == ignored:
                    return
            except ValueError:
                continue

        if os.path.islink(absolute_path):
            return

        with self._lock:
            if absolute_path in self._in_flight:
                self._dirty.add(absolute_path)
                return
            timer = self._pending.get(absolute_path)
            if timer:
                timer.cancel()
            elif len(self._pending) >= self._max_pending:
                now = time.monotonic()
                if now - self._last_queue_warning >= 60:
                    self._last_queue_warning = now
                    self.on_warning(
                        "A pasta está gerando mais eventos do que o scanner consegue enfileirar. "
                        "Alguns arquivos podem não ser verificados."
                    )
                return

            timer = threading.Timer(0.75, self._submit_scan, args=(absolute_path,))
            timer.daemon = True
            self._pending[absolute_path] = timer
            timer.start()

    def _submit_scan(self, path):
        with self._lock:
            self._pending.pop(path, None)
            if self._stopping.is_set():
                return
            self._in_flight.add(path)
        try:
            self._executor.submit(self._scan_stable_file, path)
        except RuntimeError:
            with self._lock:
                self._in_flight.discard(path)

    def _scan_stable_file(self, path):
        reschedule = False
        try:
            if not os.path.isfile(path) or os.path.islink(path):
                return
            before = os.stat(path)
            if self._stopping.wait(0.5):
                return
            after = os.stat(path)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                reschedule = True
            else:
                status = self.scanner.scan_file(path, cancel_event=self._stopping)
                if status != "Cancelled" and not self._stopping.is_set():
                    self.on_scan({"path": path, "status": status})
        except FileNotFoundError:
            return
        except OSError as error:
            logging.warning("Falha ao verificar arquivo monitorado %s: %s", path, error)
            self.on_scan({"path": path, "status": f"Error: {error}"})
        finally:
            with self._lock:
                self._in_flight.discard(path)
                reschedule = reschedule or path in self._dirty
                self._dirty.discard(path)
        if reschedule and not self._stopping.is_set():
            self._schedule_scan(path)

    def stop(self):
        self._stopping.set()
        with self._lock:
            timers = tuple(self._pending.values())
            self._pending.clear()
        for timer in timers:
            timer.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)


class RealTimeProtectionThread(QThread):
    file_scanned = pyqtSignal(dict)
    warning = pyqtSignal(str)
    status = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(self, directory, ignored_paths=()):
        super().__init__()
        self.directory = directory
        self.ignored_paths = ignored_paths
        self._running = threading.Event()
        self._observer = None
        self._handler = None

    def run(self):
        if not os.path.isdir(self.directory):
            self.status.emit(f"Diretório inválido: {self.directory}")
            self.stopped.emit()
            return

        self._running.set()
        self._handler = _FileEventHandler(
            self.directory,
            FileSignatureScanner(),
            self.file_scanned.emit,
            self.warning.emit,
            self.ignored_paths,
        )
        self._observer = Observer()
        try:
            self._observer.schedule(self._handler, self.directory, recursive=True)
            self._observer.start()
            self.status.emit(f"Monitoramento ativo: {self.directory}")
            while self._running.is_set() and self._observer.is_alive():
                self.msleep(200)
            if self._running.is_set():
                self.status.emit("O sistema de eventos de arquivos parou inesperadamente.")
        except Exception as error:
            logging.exception("Falha ao iniciar a proteção em tempo real")
            self.status.emit(f"Não foi possível monitorar a pasta: {error}")
        finally:
            self._running.clear()
            if self._observer and self._observer.is_alive():
                self._observer.stop()
                self._observer.join(timeout=3)
            if self._handler:
                self._handler.stop()
            self.stopped.emit()

    def stop(self):
        self._running.clear()
        if self._observer and self._observer.is_alive():
            self._observer.stop()
        if self._handler:
            self._handler.stop()
