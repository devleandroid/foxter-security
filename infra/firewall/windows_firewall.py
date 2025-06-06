import subprocess
import logging

class WindowsFirewall:
    def is_enabled(self):
        try:
            output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True)
            return b"State ON" in output or b"Estado ON" in output
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao verificar firewall do Windows: {str(e)}")
            return False
