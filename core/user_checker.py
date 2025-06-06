import platform
import subprocess
import logging
import pwd
import os
import time

class UserChecker:
    def get_users(self):
        unauthorized = []
        users = []
        os_name = platform.system()
        try:
            if os_name == "Linux" or os_name == "Darwin":
                for entry in pwd.getpwall():
                    username = entry.pw_name
                    users.append(username)
                    try:
                        home_dir = f"/home/{username}" if os_name == "Linux" else f"/Users/{username}"
                        if os.path.exists(home_dir):
                            ctime = os.path.getctime(home_dir)
                            if ctime > time.time() - 86400:  # Últimas 24 horas
                                unauthorized.append(username)
                                logging.warning(f"Usuário não autorizado (recente): {username}")
                    except Exception as e:
                        logging.warning(f"Erro ao verificar {username}: {str(e)}")
            elif os_name == "Windows":
                users = [user['name'] for user in win32net.NetUserEnum(None, 0)[0]]
                for u in users:
                    try:
                        user_dir = f"C:\\Users\\{u}"
                        if os.path.exists(user_dir):
                            ctime = os.path.getctime(user_dir)
                            if ctime > time.time() - 86400:  # Últimas 24 horas
                                unauthorized.append(u)
                                logging.warning(f"Usuário não autorizado (recente): {u}")
                    except Exception as e:
                        logging.warning(f"Erro ao verificar {u}: {str(e)}")
        except Exception as e:
            logging.error(f"Erro ao obter usuários: {str(e)}")
        return users, unauthorized

    def delete_user(self, username):
        os_name = platform.system()
        try:
            if os_name == "Linux":
                subprocess.check_call(["sudo", "userdel", "-r", username])
            elif os_name == "Windows":
                subprocess.check_call(f"net user {username} /delete", shell=True)
            elif os_name == "Darwin":
                subprocess.check_call(["sudo", "sysadminctl", "-deleteUser", username])
            else:
                raise Exception("Unsupported OS")
            logging.info(f"User {username} deleted")
        except subprocess.CalledProcessError as e:
            logging.error(f"Delete user {username}: {str(e)}")
            raise Exception(f"Error: {str(e)}")