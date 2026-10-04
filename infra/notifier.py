import platform
import subprocess
import logging


def _escape_applescript_string(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def notify(title, message):
    os_name = platform.system()
    try:
        if os_name == "Darwin":
            script = (
                f'display notification "{_escape_applescript_string(message)}" '
                f'with title "{_escape_applescript_string(title)}"'
            )
            subprocess.run(["osascript", "-e", script], check=True)
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