import socket
from concurrent.futures import ThreadPoolExecutor
from engine.core.logger import LoggerFactory


class TCPScanner:

    def __init__(self, target: str, start_port: int, end_port: int, threads: int = 50):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.logger = LoggerFactory.get_logger("scanner", "scan_logs")

    def scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    print(f"[OPEN] Port {port}")
                    self.logger.info(f"Port {port} is OPEN")
                else:
                    self.logger.debug(f"Port {port} is closed")

        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {str(e)}")

    def scan(self):
        print(f"\nScanning {self.target} with {self.threads} threads...\n")

        self.logger.info(
            f"Starting threaded scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            ports = range(self.start_port, self.end_port + 1)
            executor.map(self.scan_port, ports)

        self.logger.info("Scan finished.")
        print("\nScan completed.\n")
