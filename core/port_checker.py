import socket
import logging
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

class PortChecker:
    def __init__(self, host="localhost", timeout=0.5, max_threads=5):
        self.host = host
        self.timeout = timeout
        self.max_threads = max_threads
        self.lock = Lock()
        self.risky_ports = {
            3389: "RDP - High risk if public",
            22: "SSH - Check key auth",
            445: "SMB - Common attack vector",
            80: "HTTP - Potential web server",
            443: "HTTPS - Potential web server",
            8080: "HTTP-Alt - Common for proxies"
        }

    def is_port_open(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    logging.info(f"Porta {port} aberta em {self.host}")
                    return True
                return False
        except socket.gaierror as e:
            logging.error(f"Erro de resolução de host {self.host} na porta {port}: {str(e)}")
            return False
        except socket.error as e:
            logging.error(f"Erro de socket na porta {port}: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Erro inesperado na porta {port}: {str(e)}")
            return False

    def check_status(self, ports=None):
        if ports is None:
            ports = [80, 443, 8080]  # Portas não privilegiadas por padrão
        results = []
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {executor.submit(self.is_port_open, port): port for port in ports}
                for future in future_to_port:
                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                        desc = self.risky_ports.get(port, "Low risk")
                        with self.lock:
                            results.append((port, is_open, desc))
                    except Exception as e:
                        logging.error(f"Erro ao verificar porta {port}: {str(e)}")
                        with self.lock:
                            results.append((port, False, f"Error: {str(e)}"))
        except Exception as e:
            logging.error(f"Erro geral no verificador de portas: {str(e)}")
            return [], 0
        open_count = sum(1 for r in results if r[1])
        return results, open_count

    def close_port(self, port):
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return False, "Invalid port number"
        os_name = platform.system()
        try:
            if os_name == "Linux":
                subprocess.check_call(["sudo", "ufw", "deny", str(port)])
                logging.info(f"Porta {port} fechada via ufw")
                return True, f"Port {port} closed"
            elif os_name == "Windows":
                subprocess.check_call(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=FoxterBlock_{port}",
                        "dir=in",
                        "action=block",
                        "protocol=TCP",
                        f"localport={port}",
                    ]
                )
                logging.info(f"Porta {port} fechada via netsh")
                return True, f"Port {port} closed"
            elif os_name == "Darwin":
                return False, "O bloqueio de portas via pf ainda não está implementado com segurança"
            logging.warning(f"Sistema operacional não suportado para fechar porta: {os_name}")
            return False, "Unsupported OS"
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao fechar porta {port}: {str(e)}")
            return False, f"Error: {str(e)}"
        except Exception as e:
            logging.error(f"Erro inesperado ao fechar porta {port}: {str(e)}")
            return False, f"Error: {str(e)}"