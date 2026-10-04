import os
import shutil
import stat
import uuid


def quarantine_file(source_path, quarantine_directory):
    source_path = os.path.abspath(source_path)
    if os.path.islink(source_path) or not os.path.isfile(source_path):
        raise ValueError("A quarentena aceita apenas arquivos regulares, não links simbólicos")

    os.makedirs(quarantine_directory, mode=0o700, exist_ok=True)
    if os.path.islink(quarantine_directory) or not os.path.isdir(quarantine_directory):
        raise ValueError("O diretório de quarentena não é um diretório seguro")
    if os.name != "nt":
        os.chmod(quarantine_directory, 0o700)

    filename = f"{uuid.uuid4().hex}_{os.path.basename(source_path)}.quarantined"
    destination = os.path.join(quarantine_directory, filename)
    shutil.move(source_path, destination)
    if os.name != "nt":
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    return destination
