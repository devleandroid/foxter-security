import sys
import os
import logging
import platform
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget,
    QFileDialog, QLabel, QSlider, QTreeWidget, QTreeWidgetItem, QFrame, QAction, QMessageBox, QApplication
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QTimer
from core.firewall_checker import FirewallChecker
from core.port_checker import PortChecker
from core.user_checker import UserChecker
from core.process_checker import ProcessAnalyzer
from core.file_scanner import FileScannerThread
from core.quarantine import quarantine_file
from core.realtime_protection import RealTimeProtectionThread
from infra.signature_db import MALICIOUS_SIGNATURES

def get_app_data_dir():
    if platform.system() == "Windows":
        base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base_dir, "Foxter Security")
    if platform.system() == "Darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Foxter Security")
    base_dir = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))
    return os.path.join(base_dir, "foxter-security")


def resource_path(relative_path):
    bundle_dir = getattr(
        sys,
        "_MEIPASS",
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    return os.path.join(bundle_dir, relative_path)


APP_DATA_DIR = get_app_data_dir()
os.makedirs(APP_DATA_DIR, mode=0o700, exist_ok=True)
if os.name != "nt":
    os.chmod(APP_DATA_DIR, 0o700)
logging.basicConfig(
    filename=os.path.join(APP_DATA_DIR, "antivirus.log"),
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

QUARANTINE_DIR = os.path.join(APP_DATA_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, mode=0o700, exist_ok=True)
if os.name != "nt":
    os.chmod(QUARANTINE_DIR, 0o700)

class NeonButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Arial", 10))
        self.setFixedHeight(40)
        self.setStyleSheet("""
            QPushButton {
                background-color: #8E44AD;
                color: #FFFFFF;
                border: none;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #9B59B6;
            }
            QPushButton:pressed {
                background-color: #7D3C98;
            }
        """)
        self.setCursor(Qt.PointingHandCursor)

class StatusLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QLabel {
                background-color: #34495E;
                color: #FFFFFF;
                padding: 10px;
                border-radius: 5px;
                font-family: Arial;
                font-size: 10pt;
            }
        """)
        self.setWordWrap(True)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Foxter Security - Antivírus")
        icon_path = resource_path("fox.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.resize(900, 500)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1F2A44;
            }
            QLabel {
                color: #FFFFFF;
                font-family: Arial;
                font-size: 12pt;
            }
            QTreeWidget {
                background-color: #2C3E50;
                color: #FFFFFF;
                border: 1px solid #00CED1;
                border-radius: 5px;
                font-family: Arial;
                font-size: 10pt;
            }
            QTreeWidget::item:hover {
                background-color: #34495E;
            }
            QSlider::groove:horizontal {
                border: 1px solid #8e44ad;
                height: 8px;
                background: #2C3E50;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #8E44AD;
                border: 1px solid #00CED1;
                width: 18px;
                margin: -2px 0;
                border-radius: 9px;
            }
        """)
        self.setFont(QFont("Arial", 10))

        # Inicialização
        self.file_scanner = None
        self.realtime_protection = None
        self.firewall_checker = FirewallChecker()
        self.port_checker = PortChecker()
        self.user_checker = UserChecker()
        self.process_analyzer = ProcessAnalyzer()

        # Layout principal
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)

        # Barra de navegação
        self.nav_frame = QFrame()
        self.nav_frame.setStyleSheet("background-color: #2C3E50; border-radius: 5px;")
        self.nav_layout = QHBoxLayout(self.nav_frame)
        self.nav_layout.setContentsMargins(5, 5, 5, 5)
        self.nav_buttons = []
        sections = ["Scanner", "Firewall", "Portas", "Processos", "Usuários"]
        for i, section in enumerate(sections):
            btn = NeonButton(section)
            btn.clicked.connect(lambda _, idx=i: self.stack.setCurrentIndex(idx))
            self.nav_layout.addWidget(btn)
            self.nav_buttons.append(btn)
        self.main_layout.addWidget(self.nav_frame)

        # Stack de painéis
        self.stack = QStackedWidget()
        self.main_layout.addWidget(self.stack)

        # Painel Scanner
        self.scanner_panel = QWidget()
        self.scanner_layout = QHBoxLayout(self.scanner_panel)
        self.setup_scanner_panel()
        self.stack.addWidget(self.scanner_panel)

        # Painel Firewall
        self.firewall_panel = QWidget()
        self.firewall_layout = QHBoxLayout(self.firewall_panel)
        self.setup_firewall_panel()
        self.stack.addWidget(self.firewall_panel)

        # Painel Portas
        self.ports_panel = QWidget()
        self.ports_layout = QHBoxLayout(self.ports_panel)
        self.setup_ports_panel()
        self.stack.addWidget(self.ports_panel)

        # Painel Processos
        self.processes_panel = QWidget()
        self.processes_layout = QHBoxLayout(self.processes_panel)
        self.setup_processes_panel()
        self.stack.addWidget(self.processes_panel)

        # Painel Usuários
        self.users_panel = QWidget()
        self.users_layout = QHBoxLayout(self.users_panel)
        self.setup_users_panel()
        self.stack.addWidget(self.users_panel)

        # Monitoramento
        self.monitor_interval = 60000
        self.real_time_check = QTimer()  # Correção: Definido como real_time_check
        self.real_time_check.timeout.connect(self.check_suspicious_processes)
        self.real_time_check.start(self.monitor_interval)

    def setup_scanner_panel(self):
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setAlignment(Qt.AlignTop)
        controls_widget.setFixedWidth(250)
        controls_widget.setStyleSheet("background-color: #2C3E50; border-radius: 5px; padding: 5px;")

        self.select_dir_button = NeonButton("Selecionar Diretório")
        self.select_dir_button.setToolTip("Escolha um diretório")
        self.select_dir_button.clicked.connect(self.select_directory)
        controls_layout.addWidget(self.select_dir_button)

        self.scan_button = NeonButton("Iniciar Escaneamento")
        self.scan_button.setToolTip("Escanear arquivos")
        self.scan_button.clicked.connect(self.run_file_scan)
        controls_layout.addWidget(self.scan_button)

        self.scanner_status = StatusLabel("Aguardando escaneamento...")
        controls_layout.addWidget(self.scanner_status)

        self.monitor_status = StatusLabel("Proteção em tempo real desativada.")
        controls_layout.addWidget(self.monitor_status)

        self.monitor_button = NeonButton("Ativar proteção em tempo real")
        self.monitor_button.setToolTip(
            "Monitorar esta pasta selecionada. A proteção é heurística e não bloqueia arquivos automaticamente."
        )
        self.monitor_button.clicked.connect(self.start_realtime_protection)
        controls_layout.addWidget(self.monitor_button)

        self.stop_monitor_button = NeonButton("Parar proteção em tempo real")
        self.stop_monitor_button.setEnabled(False)
        self.stop_monitor_button.clicked.connect(self.stop_realtime_protection)
        controls_layout.addWidget(self.stop_monitor_button)

        save_report_btn = NeonButton("Salvar Relatório")
        save_report_btn.setToolTip("Salvar resultados")
        save_report_btn.clicked.connect(self.save_report)
        controls_layout.addWidget(save_report_btn)

        self.scanner_layout.addWidget(controls_widget)

        self.scan_results_tree = QTreeWidget()
        self.scan_results_tree.setHeaderLabels(["Arquivo", "Status", "Ação"])
        self.scan_results_tree.setColumnWidth(0, 300)
        self.scan_results_tree.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.quarantine_action = QAction("Mover para Quarentena", self)
        self.quarantine_action.triggered.connect(self.quarantine_file)
        self.delete_action = QAction("Excluir", self)
        self.delete_action.triggered.connect(self.delete_file)
        self.scan_results_tree.addAction(self.quarantine_action)
        self.scan_results_tree.addAction(self.delete_action)
        self.scanner_layout.addWidget(self.scan_results_tree)

    def setup_firewall_panel(self):
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setAlignment(Qt.AlignTop)
        controls_widget.setFixedWidth(250)
        controls_widget.setStyleSheet("background-color: #2C3E50; border-radius: 5px; padding: 5px;")

        self.firewall_status = StatusLabel("Status do Firewall: --")
        controls_layout.addWidget(self.firewall_status)

        check_firewall_btn = NeonButton("Verificar Firewall")
        check_firewall_btn.setToolTip("Checar firewall")
        check_firewall_btn.clicked.connect(self.check_firewall_status)
        controls_layout.addWidget(check_firewall_btn)

        fix_firewall_btn = NeonButton("Corrigir Firewall")
        fix_firewall_btn.setToolTip("Ativar firewall")
        fix_firewall_btn.clicked.connect(self.fix_firewall)
        controls_layout.addWidget(fix_firewall_btn)

        self.firewall_layout.addWidget(controls_widget)

        self.firewall_threats_tree = QTreeWidget()
        self.firewall_threats_tree.setHeaderLabels(["Ameaça", "Descrição"])
        self.firewall_threats_tree.setColumnWidth(0, 200)
        self.firewall_layout.addWidget(self.firewall_threats_tree)

    def setup_ports_panel(self):
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setAlignment(Qt.AlignTop)
        controls_widget.setFixedWidth(250)
        controls_widget.setStyleSheet("background-color: #2C3E50; border-radius: 5px; padding: 5px;")

        check_ports_btn = NeonButton("Checar Portas")
        check_ports_btn.setToolTip("Verificar portas")
        check_ports_btn.clicked.connect(self.check_ports)
        controls_layout.addWidget(check_ports_btn)

        self.ports_status = StatusLabel("Aguardando verificação...")
        controls_layout.addWidget(self.ports_status)

        self.ports_layout.addWidget(controls_widget)

        self.ports_tree = QTreeWidget()
        self.ports_tree.setHeaderLabels(["Porta", "Status", "Risco", "Ação"])
        self.ports_tree.setColumnWidth(0, 100)
        self.ports_tree.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.close_port_action = QAction("Fechar Porta", self)
        self.close_port_action.triggered.connect(self.close_port)
        self.ports_tree.addAction(self.close_port_action)
        self.ports_layout.addWidget(self.ports_tree)

    def setup_processes_panel(self):
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setAlignment(Qt.AlignTop)
        controls_widget.setFixedWidth(250)
        controls_widget.setStyleSheet("background-color: #2C3E50; border-radius: 5px; padding: 5px;")

        check_proc_btn = NeonButton("Detectar Processos")
        check_proc_btn.setToolTip("Identificar processos")
        check_proc_btn.clicked.connect(self.check_suspicious_processes)
        controls_layout.addWidget(check_proc_btn)

        interval_label = QLabel("Intervalo de Monitoramento (s):")
        controls_layout.addWidget(interval_label)

        self.interval_slider = QSlider(Qt.Horizontal)
        self.interval_slider.setMinimum(10)
        self.interval_slider.setMaximum(300)
        self.interval_slider.setValue(60)
        self.interval_slider.setToolTip("Ajustar intervalo")
        self.interval_slider.valueChanged.connect(self.update_monitor_interval)
        controls_layout.addWidget(self.interval_slider)

        self.processes_status = StatusLabel("Aguardando verificação...")
        controls_layout.addWidget(self.processes_status)

        self.processes_layout.addWidget(controls_widget)

        self.processes_tree = QTreeWidget()
        self.processes_tree.setHeaderLabels(["PID", "Nome", "Usuário", "Solução"])
        self.processes_tree.setColumnWidth(0, 100)
        self.processes_tree.setColumnWidth(1, 200)
        self.processes_tree.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.terminate_action = QAction("Encerrar Processo", self)
        self.terminate_action.triggered.connect(self.terminate_process)
        self.processes_tree.addAction(self.terminate_action)
        self.processes_layout.addWidget(self.processes_tree)

    def setup_users_panel(self):
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setAlignment(Qt.AlignTop)
        controls_widget.setFixedWidth(250)
        controls_widget.setStyleSheet("background-color: #2C3E50; border-radius: 5px; padding: 5px;")

        check_users_btn = NeonButton("Verificar Usuários")
        check_users_btn.setToolTip("Listar usuários")
        check_users_btn.clicked.connect(self.check_users)
        controls_layout.addWidget(check_users_btn)

        self.users_status = StatusLabel("Aguardando verificação...")
        controls_layout.addWidget(self.users_status)

        self.users_layout.addWidget(controls_widget)

        self.users_tree = QTreeWidget()
        self.users_tree.setHeaderLabels(["Usuário", "Status", "Ação"])
        self.users_tree.setColumnWidth(0, 200)
        self.users_tree.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.remove_user_action = QAction("Remover Usuário", self)
        self.remove_user_action.triggered.connect(self.remove_user)
        self.users_tree.addAction(self.remove_user_action)
        self.users_layout.addWidget(self.users_tree)

    def select_directory(self):
        default_dir = os.path.expanduser("~")
        directory = QFileDialog.getExistingDirectory(self, "Selecionar Diretório", default_dir)
        if directory:
            self.file_scanner = FileScannerThread(directory=directory)
            self.file_scanner.progress.connect(self.update_progress)
            self.file_scanner.batch_scanned.connect(self.update_scan_result)
            self.file_scanner.finished.connect(self.display_scan_results)
            self.scan_results_tree.clear()
            self.scanner_status.setText(f"Diretório selecionado: {directory}")
            logging.info(f"Diretório selecionado: {directory}")

    def run_file_scan(self):
        if not self.file_scanner:
            self.scanner_status.setText("Erro: Selecione um diretório!")
            return
        if self.file_scanner.isRunning():
            return
        self.scan_results_tree.clear()
        self.scanner_status.setText("Escaneando...")
        self.select_dir_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.file_scanner.start()

    def update_progress(self, value):
        self.scanner_status.setText(f"Arquivos verificados: {value}")

    def update_scan_result(self, batch):
        for result in batch:
            item = QTreeWidgetItem([result["path"], result["status"], ""])
            self.scan_results_tree.addTopLevelItem(item)
        self.scan_results_tree.scrollToBottom()

    def display_scan_results(self, results):
        self.select_dir_button.setEnabled(True)
        self.scan_button.setEnabled(True)
        suspicious = [r for r in results if r["status"] == "Suspicious"]
        self.scanner_status.setText(f"Concluído: {len(suspicious)} ameaças encontradas.")
        item = QTreeWidgetItem([f"Total: {len(results)}", "", ""])
        self.scan_results_tree.addTopLevelItem(item)
        item = QTreeWidgetItem([f"Ameaças: {len(suspicious)}", "", ""])
        self.scan_results_tree.addTopLevelItem(item)
        logging.info(f"Escaneamento: {len(results)} total, {len(suspicious)} suspeitos")

    def start_realtime_protection(self):
        if not self.file_scanner:
            self.monitor_status.setText("Selecione uma pasta antes de ativar o monitoramento.")
            return
        if self.realtime_protection and self.realtime_protection.isRunning():
            return

        directory = self.file_scanner.directory
        self.realtime_protection = RealTimeProtectionThread(
            directory,
            ignored_paths=(QUARANTINE_DIR,),
        )
        self.realtime_protection.file_scanned.connect(self.display_monitored_file)
        self.realtime_protection.warning.connect(self.show_protection_warning)
        self.realtime_protection.status.connect(self.monitor_status.setText)
        self.realtime_protection.stopped.connect(self.finish_realtime_protection)
        self.select_dir_button.setEnabled(False)
        self.monitor_button.setEnabled(False)
        self.stop_monitor_button.setEnabled(True)
        self.realtime_protection.start()

    def stop_realtime_protection(self):
        if self.realtime_protection and self.realtime_protection.isRunning():
            self.stop_monitor_button.setEnabled(False)
            self.monitor_status.setText("Parando a proteção em tempo real...")
            self.realtime_protection.stop()

    def finish_realtime_protection(self):
        if self.monitor_status.text().startswith(
            ("Monitoramento ativo:", "Parando a proteção em tempo real...")
        ):
            self.monitor_status.setText("Proteção em tempo real desativada.")
        self.select_dir_button.setEnabled(True)
        self.monitor_button.setEnabled(True)
        self.stop_monitor_button.setEnabled(False)

    def display_monitored_file(self, result):
        item = QTreeWidgetItem([result["path"], result["status"], ""])
        self.scan_results_tree.addTopLevelItem(item)
        while self.scan_results_tree.topLevelItemCount() > 1000:
            self.scan_results_tree.takeTopLevelItem(0)
        self.monitor_status.setText(
            f"Monitoramento: {result['status']} — {result['path']}"
        )

    def show_protection_warning(self, message):
        self.monitor_status.setText(message)
        QMessageBox.warning(self, "Alerta de proteção", message)

    def quarantine_file(self):
        item = self.scan_results_tree.currentItem()
        if item and item.text(1) == "Suspicious":
            path = item.text(0)
            answer = QMessageBox.question(
                self,
                "Confirmar quarentena",
                f"Mover este arquivo para a quarentena?\n\n{path}",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            try:
                quarantine_file(path, QUARANTINE_DIR)
                item.setText(2, "Em quarentena")
                self.scanner_status.setText(f"{path} movido para quarentena.")
                logging.info(f"Quarentena: {path}")
            except Exception as e:
                self.scanner_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro quarentena: {str(e)}")

    def delete_file(self):
        item = self.scan_results_tree.currentItem()
        if item and item.text(1) == "Suspicious":
            path = item.text(0)
            answer = QMessageBox.question(
                self,
                "Confirmar exclusão",
                f"Excluir permanentemente este arquivo?\n\n{path}",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            try:
                os.remove(path)
                item.setText(2, "Excluído")
                self.scanner_status.setText(f"{path} excluído.")
                logging.info(f"Excluído: {path}")
            except Exception as e:
                self.scanner_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro exclusão: {str(e)}")

    def save_report(self):
        if self.scan_results_tree.topLevelItemCount() == 0:
            self.scanner_status.setText("Erro: Nenhum resultado!")
            return
        file_name, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "", "Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, "w") as f:
                    for i in range(self.scan_results_tree.topLevelItemCount()):
                        item = self.scan_results_tree.topLevelItem(i)
                        f.write(f"{item.text(0)} - {item.text(1)} - {item.text(2)}\n")
                self.scanner_status.setText("Relatório salvo!")
                logging.info(f"Relatório: {file_name}")
            except Exception as e:
                self.scanner_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro relatório: {str(e)}")

    def check_firewall_status(self):
        status, threats = self.firewall_checker.check_status()
        texto = "Active" if status else "Inactive"
        self.firewall_status.setText(f"Firewall: {texto}")
        self.firewall_threats_tree.clear()
        if threats:
            for threat, desc in threats:
                item = QTreeWidgetItem([threat, desc])
                self.firewall_threats_tree.addTopLevelItem(item)
            self.firewall_status.setText(f"{self.firewall_status.text()} | {len(threats)} ameaças")
        else:
            item = QTreeWidgetItem(["None", "Firewall seguro"])
            self.firewall_threats_tree.addTopLevelItem(item)
        logging.info(f"Firewall: {status}, ameaças: {len(threats)}")

    def fix_firewall(self):
        try:
            success, message = self.firewall_checker.fix()
            if success:
                self.firewall_status.setText(message)
                self.check_firewall_status()
                logging.info(f"Correção firewall: {message}")
            else:
                self.firewall_status.setText(f"Falha: {message}")
                QMessageBox.warning(self, "Erro", f"Não foi possível corrigir o firewall: {message}")
                logging.warning(f"Falha ao corrigir firewall: {message}")
        except Exception as e:
            error_msg = f"Erro inesperado ao corrigir o firewall: {str(e)}"
            self.firewall_status.setText(error_msg)
            QMessageBox.critical(self, "Erro Crítico", error_msg)
            logging.error(f"Erro correção firewall: {str(e)}")

    def check_ports(self):
        self.ports_tree.clear()
        try:
            results, open_count = self.port_checker.check_status()
            for port, is_open, desc in results:
                status = "Open" if is_open else "Closed"
                item = QTreeWidgetItem([str(port), status, desc, ""])
                self.ports_tree.addTopLevelItem(item)
            self.ports_status.setText(f"Concluído: {open_count} portas abertas")
            logging.info(f"Portas: {open_count} abertas")
        except Exception as e:
            self.ports_status.setText(f"Erro ao verificar portas: {str(e)}")
            logging.error(f"Erro ao verificar portas: {str(e)}")

    def close_port(self):
        item = self.ports_tree.currentItem()
        if item and item.text(1) == "Open":
            port = int(item.text(0))
            answer = QMessageBox.question(
                self,
                "Confirmar bloqueio",
                f"Adicionar uma regra de bloqueio de entrada para a porta {port}?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            try:
                success, message = self.port_checker.close_port(port)
                item.setText(3, message)
                self.ports_status.setText(message)
                self.check_ports()
                logging.info(f"Fechar porta {port}: {message}")
            except Exception as e:
                self.ports_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro fechar porta {port}: {str(e)}")

    def check_suspicious_processes(self):
        self.processes_tree.clear()
        processes = self.process_analyzer.detect_suspicious()
        for p in processes:
            solution = "Encerrar via menu"
            item = QTreeWidgetItem([str(p["pid"]), p["name"], p["username"], solution])
            self.processes_tree.addTopLevelItem(item)
        self.processes_status.setText(f"{len(processes)} ameaças suspeitas")
        logging.info(f"Processos: {len(processes)} suspeitos")

    def terminate_process(self):
        item = self.processes_tree.currentItem()
        if item:
            pid = int(item.text(0))
            answer = QMessageBox.question(
                self,
                "Confirmar encerramento",
                f"Tentar encerrar o processo {item.text(1)} (PID {pid})?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            try:
                self.process_analyzer.terminate_process(pid)
                item.setText(3, "Encerrado")
                self.processes_status.setText(f"Processo {pid} encerrado")
                logging.info(f"Processo {pid} encerrado")
            except Exception as e:
                self.processes_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro encerrar {pid}: {str(e)}")

    def check_users(self):
        self.users_tree.clear()
        users, unauthorized = self.user_checker.get_users()
        for u in users:
            status = "Unauthorized" if u in unauthorized else "Authorized"
            item = QTreeWidgetItem([u, status, ""])
            self.users_tree.addTopLevelItem(item)
        self.users_status.setText(f"{len(users)} usuários, {len(unauthorized)} não autorizados")
        logging.info(f"Usuários: {len(users)}, não autorizados: {len(unauthorized)}")

    def remove_user(self):
        item = self.users_tree.currentItem()
        if item and item.text(1) == "Unauthorized":
            username = item.text(0)
            answer = QMessageBox.question(
                self,
                "Confirmar remoção de usuário",
                f"Remover a conta {username} e, quando suportado, seus arquivos pessoais?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            try:
                self.user_checker.delete_user(username)
                item.setText(2, "Removido")
                self.users_status.setText(f"Usuário {username} removido")
                logging.info(f"Usuário {username} removido")
            except Exception as e:
                self.users_status.setText(f"Erro: {str(e)}")
                logging.error(f"Erro remover {username}: {str(e)}")

    def update_monitor_interval(self, value):
        self.monitor_interval = value * 1000
        self.real_time_check.setInterval(self.monitor_interval)
        self.processes_status.setText(f"Intervalo: {value} segundos")
        logging.info(f"Intervalo: {value} segundos")

    def closeEvent(self, event):
        if self.realtime_protection and self.realtime_protection.isRunning():
            self.realtime_protection.stop()
            self.realtime_protection.wait(3000)
        if self.file_scanner and self.file_scanner.isRunning():
            self.file_scanner.stop()
            self.file_scanner.wait(3000)
        super().closeEvent(event)

def check_dependencies():
    missing = []
    if platform.system() == "Linux":
        if not shutil.which("ufw"):  # Apenas avisa, mas não bloqueia
            print("Aviso: ufw não encontrado. Funcionalidade de firewall pode estar limitada.")
        if not shutil.which("python3"):
            missing.append("python3")
    return missing

if __name__ == "__main__":
    missing = check_dependencies()
    if missing:
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        label = StatusLabel(f"Erro: Instale {', '.join(missing)}")
        label.show()
        sys.exit(app.exec_())
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())