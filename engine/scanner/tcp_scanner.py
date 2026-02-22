import socket
from colorama import Fore, Style
from engine.scanner.base_scanner import BaseScanner
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from engine.utils.severity_classifier import SeverityClassifier


class TCPScanner(BaseScanner):

    def __init__(self, target, start_port, end_port, threads=50, timeout=1.0):
        logger = LoggerFactory.get_logger("tcp_scanner", "scan_logs")
        super().__init__(target, start_port, end_port, threads, timeout, logger)

    # -------------------------------------------------------
    # Vulnerability Pattern Check
    # -------------------------------------------------------
    def check_vulnerability(self, port: int, banner: str):
        if not banner:
            return

        banner_lower = banner.lower()

        vulnerable_patterns = [
            "apache/2.2",
            "openssh_5",
            "simplehttp",
            "php/5"
        ]

        for pattern in vulnerable_patterns:
            if pattern in banner_lower:
                warning_msg = f"Potential vulnerable service detected on port {port}: {pattern}"
                print(f"{Fore.RED}⚠ {warning_msg}{Style.RESET_ALL}")
                self.logger.warning(warning_msg)

    # -------------------------------------------------------
    # Scan Single TCP Port
    # -------------------------------------------------------
    def scan_port(self, port: int):

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    service = ServiceMapper.get_service_name(port)
                    banner_text = None

                    # Attempt banner grabbing
                    try:
                        sock.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()

                        if banner:
                            banner_text = banner[:200]
                            self.logger.info(f"Port {port} banner: {banner_text}")
                            self.check_vulnerability(port, banner)

                    except Exception:
                        pass

                    severity = SeverityClassifier.classify(port, banner_text)

                    color = {
                        "high": Fore.RED,
                        "medium": Fore.YELLOW,
                        "low": Fore.GREEN
                    }.get(severity, Fore.GREEN)

                    # Thread-safe result update
                    with self.result_lock:
                        print(
                            f"{color}[OPEN] Port {port} | "
                            f"Service: {service} | "
                            f"Severity: {severity.upper()}"
                            f"{Style.RESET_ALL}"
                        )

                        if banner_text:
                            print(f"   └─ Banner: {banner_text[:100]}")

                        self.open_ports.append({
                            "port": port,
                            "service": service,
                            "banner": banner_text,
                            "severity": severity,
                            "status": "open"
                        })

                    self.logger.info(f"Port {port} is OPEN")

                else:
                    self.logger.debug(f"Port {port} is closed")

        except Exception as e:
            self.logger.error(f"Error scanning TCP port {port}: {str(e)}")

        finally:
            with self.progress_lock:
                self.scanned_ports += 1
                self._print_progress()

    # -------------------------------------------------------
    # Start TCP Scan
    # -------------------------------------------------------
    def scan(self):
        self.logger.info(
            f"Starting TCP scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )

        return self._run_scan(self.scan_port)