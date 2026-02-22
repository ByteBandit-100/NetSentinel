import subprocess
import platform

class HostDiscovery:

    @staticmethod
    def is_host_alive(ip: str) -> bool:
        system = platform.system().lower()

        if system == "windows":
            command = ["ping", "-n", "1", "-w", "500", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False