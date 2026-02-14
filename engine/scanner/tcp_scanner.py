import socket
import time
from engine.utils.severity_classifier import SeverityClassifier
from concurrent.futures import ThreadPoolExecutor
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from colorama import Fore, Style
import threading

class TCPScanner:

    def __init__(self, target: str, start_port: int, end_port: int, threads: int = 50):
        self.target = target
        self.lock = threading.Lock()
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.logger = LoggerFactory.get_logger("scanner", "scan_logs")
        self.open_ports = []

    def check_vulnerability(self, port: int, banner: str):
        banner_lower = banner.lower()

        vulnerable_patterns = [
            "apache/2.2",
            "openssh_5",
            "simplehttp",
            "php/5"
        ]

        for pattern in vulnerable_patterns:
            if pattern in banner_lower:
                warning_msg = (
                    f"Potential vulnerable service detected on port {port}: {pattern}"
                )
                print(f"  ⚠ {warning_msg}")
                self.logger.warning(warning_msg)

    def scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    self.logger.info(f"Port {port} is OPEN")

                    service = ServiceMapper.get_service_name(port)
                    banner_text = None

                    # Attempt banner grabbing
                    try:
                        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()

                        if banner:
                            banner_text = banner[:200]
                            print(f"  └─ Banner: {banner[:100]}")
                            self.logger.info(f"Port {port} banner: {banner_text}")
                            self.check_vulnerability(port, banner)

                    except:
                        pass

                    severity = SeverityClassifier.classify(port, banner_text)

                    color = {
                        "high": Fore.RED,
                        "medium": Fore.YELLOW,
                        "low": Fore.GREEN
                    }.get(severity, Fore.GREEN)

                    with self.lock:
                        print(
                            f"{color}[OPEN] Port {port} | "
                            f"Severity: {severity.upper()}{Style.RESET_ALL}"
                        )

                        self.open_ports.append({
                            "port": port,
                            "service": service,
                            "banner": banner_text,
                            "severity": severity
                        })

                else:
                    self.logger.debug(f"Port {port} is closed")

        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {str(e)}")

    def scan(self):
        print(f"\nScanning {self.target} with {self.threads} threads...\n")

        start_time = time.time()

        self.logger.info(
            f"Starting threaded scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            ports = range(self.start_port, self.end_port + 1)
            executor.map(self.scan_port, ports)

        end_time = time.time()
        duration = round(end_time - start_time, 2)

        total_ports = self.end_port - self.start_port + 1
        open_count = len(self.open_ports)

        print("\nScan Summary")
        print("------------")
        print(f"Target: {self.target}")
        print(f"Ports scanned: {total_ports}")
        print(f"Open ports: {open_count}")
        print(f"Time taken: {duration} seconds\n")

        self.logger.info("Scan finished.")
        self.logger.info(
            f"Summary: {open_count} open ports found in {duration} seconds"
        )
        return self.open_ports

