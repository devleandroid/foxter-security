import logging
import re
from pathlib import Path

import requests


VERSION_URL = (
    "https://raw.githubusercontent.com/devleandroid/foxter-security/main/VERSION"
)
VERSION_PATTERN = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
MAX_VERSION_RESPONSE_BYTES = 64


def _parse_version(value):
    match = VERSION_PATTERN.fullmatch(value)
    if not match:
        raise ValueError("Formato de versão remota inválido")
    return tuple(int(part) for part in match.groups())


def check_for_updates():
    try:
        with requests.get(
            VERSION_URL,
            timeout=(3.05, 5),
            stream=True,
        ) as response:
            response.raise_for_status()
            version_bytes = bytearray()
            for chunk in response.iter_content(chunk_size=MAX_VERSION_RESPONSE_BYTES + 1):
                version_bytes.extend(chunk)
                if len(version_bytes) > MAX_VERSION_RESPONSE_BYTES:
                    raise ValueError("Resposta de versão excede o limite permitido")

        remote_version = version_bytes.decode("utf-8").strip()
        remote_parts = _parse_version(remote_version)
        version_file = Path(__file__).resolve().parents[1] / "VERSION"
        local_version = version_file.read_text(encoding="utf-8").strip()
        local_parts = _parse_version(local_version)
        return remote_parts > local_parts, remote_version
    except (requests.RequestException, OSError, UnicodeError, ValueError) as error:
        logging.error("Erro ao verificar atualizações: %s", error)
        return False, f"Erro: {error}"
