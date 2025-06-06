import platform
import subprocess
import os
import logging

def notify(title, message):
    os_name = platform.system()
    try:
        if os_name == "Darwin":
            os.system(f'''osascript -e 'display notification "{message}" with title "{title}"' ''')
        elif os_name == "Linux":
            subprocess.call(["notify-send", title, message])
        elif os_name == "Windows":
            try:
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(title, message, duration=5)
            except ImportError:
                logging.warning("win10toast não está instalado. Notificações no Windows desativadas.")
    except Exception as e:
        logging.error(f"Erro ao enviar notificação: {str(e)}")