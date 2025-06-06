import subprocess
import shutil
import logging

class LinuxFirewall:
    def is_enabled(self):
        if not shutil.which("ufw"):
            logging.error("Comando ufw não encontrado")
            return False
        try:
            output = subprocess.check_output(["ufw", "status"]).decode()
            return "inactive" not in output.lower()
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao verificar status do ufw: {str(e)}")
            return False
