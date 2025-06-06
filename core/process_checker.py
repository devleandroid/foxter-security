import psutil
import logging

class ProcessAnalyzer:
    def __init__(self):
        self.last_processes = {}
        self.suspicious_names = ["keylogger", "malware", "botnet", "stealer"]

    def detect_suspicious(self):
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                info = proc.info
                if not info.get('username'):
                    continue
                pid = info['pid']
                name = info['name'].lower() if info['name'] else ""
                # Heurísticas
                if any(term in name for term in self.suspicious_names):
                    info['suspeito'] = True
                elif info['cpu_percent'] > 80 or info['memory_percent'] > 50:
                    info['suspeito'] = True
                    logging.warning(f"Suspeito (recursos): {name}, PID: {pid}")
                else:
                    info['suspeito'] = False
                if info['suspeito']:
                    suspicious.append(info)
                self.last_processes[pid] = info
        except Exception as e:
            logging.error(f"Process detect error: {str(e)}")
        return suspicious

    def terminate_process(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
        except psutil.NoSuchProcess:
            raise Exception("Process not found")
        except psutil.TimeoutExpired:
            process.kill()
            raise Exception("Process forcibly terminated")
        except Exception as e:
            raise Exception(f"Error: {str(e)}")