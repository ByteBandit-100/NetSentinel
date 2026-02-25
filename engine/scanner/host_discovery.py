import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class HostDiscovery:

    stop_event = threading.Event()

    @staticmethod
    def is_host_alive(ip: str, timeout: float = 0.5) -> bool:
        system = platform.system().lower()

        if system == "windows":
            command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            command = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False

    @classmethod
    def discover_hosts(cls, targets, threads=100, timeout=0.5):
        alive_hosts = []

        def ping(ip):
            if cls.stop_event.is_set():
                return None

            if cls.is_host_alive(ip, timeout):
                return ip
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(ping, ip) for ip in targets]

            try:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        alive_hosts.append(result)

            except KeyboardInterrupt:
                print("\n[!] Host discovery interrupted.")
                cls.stop_event.set()
                executor.shutdown(wait=False, cancel_futures=True)

        return alive_hosts