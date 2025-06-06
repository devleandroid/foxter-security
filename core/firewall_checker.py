import platform
import subprocess
import logging
import shutil

class FirewallChecker:
    def __init__(self):
        self.threats = {
            "Port 445 open": "SMB - Common attack vector",
            "No firewall active": "System unprotected"
        }

    def check_status(self):
        os_name = platform.system()
        threats = []
        try:
            if os_name == "Linux":
                if not shutil.which("ufw"):
                    return False, [("Dependency missing", "ufw not installed. Install it with 'sudo apt-get install ufw'")]
                result = subprocess.check_output(["ufw", "status"], text=True)
                active = "Status: active" in result
                if not active:
                    threats.append(("No firewall active", self.threats["No firewall active"]))
                if "445" in result:
                    threats.append(("Port 445 open", self.threats["Port 445 open"]))
            elif os_name == "Windows":
                result = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
                active = "ON" in result.upper()
                if not active:
                    threats.append(("No firewall active", self.threats["No firewall active"]))
                if "445" in result:
                    threats.append(("Port 445 open", self.threats["Port 445 open"]))
            elif os_name == "Darwin":
                result = subprocess.check_output(["sudo", "pfctl", "-s", "info"], text=True)
                active = "enabled" in result
                if not active:
                    threats.append(("No firewall active", self.threats["No firewall active"]))
                if "445" in result:
                    threats.append(("Port 445 open", self.threats["Port 445 open"]))
            else:
                return False, [("Unsupported OS", "Firewall check not implemented")]
            return active, threats
        except subprocess.CalledProcessError as e:
            logging.error(f"Firewall check error: {str(e)}")
            return False, [("Error", f"Failed to check firewall status: {str(e)}")]
        except Exception as e:
            logging.error(f"Unexpected firewall check error: {str(e)}")
            return False, [("Error", f"Unexpected error: {str(e)}")]

    def fix(self):
        os_name = platform.system()
        try:
            if os_name == "Linux":
                if not shutil.which("ufw"):
                    return False, "ufw not installed. Install it with 'sudo apt-get install ufw'"
                subprocess.check_call(["sudo", "ufw", "enable"])
                return True, "Firewall ativado com sucesso"
            elif os_name == "Windows":
                subprocess.check_call("netsh advfirewall set allprofiles state on", shell=True)
                return True, "Firewall ativado com sucesso (execute como administrador se falhar)"
            elif os_name == "Darwin":
                subprocess.check_call(["sudo", "pfctl", "-E"])
                return True, "Firewall ativado com sucesso"
            return False, "Sistema operacional não suportado"
        except subprocess.CalledProcessError as e:
            logging.error(f"Firewall fix error: {str(e)}")
            if os_name == "Linux":
                return False, "Erro ao ativar o firewall: execute o programa com sudo"
            elif os_name == "Windows":
                return False, "Erro ao ativar o firewall: execute como administrador"
            elif os_name == "Darwin":
                return False, "Erro ao ativar o firewall: execute com sudo"
            return False, f"Erro ao ativar o firewall: {str(e)}"
        except Exception as e:
            logging.error(f"Unexpected firewall fix error: {str(e)}")
            return False, f"Erro inesperado: {str(e)}"