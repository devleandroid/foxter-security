import requests

def check_for_updates():
    url = "https://raw.githubusercontent.com/seuusuario/foxter-security/main/VERSION"
    try:
        remote_version = requests.get(url).text.strip()
        with open("VERSION", "r") as f:
            local_version = f.read().strip()
        if remote_version != local_version:
            return True, remote_version
        return False, local_version
    except Exception as e:
        return False, f"Erro: {e}"
