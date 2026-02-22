import socket
from colorama import Fore, Style
from engine.scanner.base_scanner import BaseScanner
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from engine.utils.severity_classifier import SeverityClassifier


class UDPScanner(BaseScanner):

    def __init__(self, target, start_port, end_port, threads=50, timeout=1.0):
        logger = LoggerFactory.get_logger("udp_scanner", "scan_logs")
        super().__init__(target, start_port, end_port, threads, timeout, logger)

    # -------------------------------------------------------
    # Scan Single UDP Port
    # -------------------------------------------------------
    def scan_port(self, port: int):

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)

                sock.sendto(b"test", (self.target, port))

                service = ServiceMapper.get_service_name(port)
                banner_text = None

                try:
                    data, _ = sock.recvfrom(1024)
                    banner_text = data.decode(errors="ignore").strip()[:200]
                    status = "open"

                except socket.timeout:
                    status = "open|filtered"

                except ConnectionResetError:
                    return  # Closed port

                severity = SeverityClassifier.classify(port, banner_text)

                color = {
                    "high": Fore.RED,
                    "medium": Fore.YELLOW,
                    "low": Fore.GREEN
                }.get(severity, Fore.GREEN)

                with self.result_lock:
                    print(
                        f"{color}[{status.upper()}] UDP Port {port} | "
                        f"Service: {service} | "
                        f"Severity: {severity.upper()}"
                        f"{Style.RESET_ALL}"
                    )

                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner_text,
                        "severity": severity,
                        "status": status
                    })

        except Exception as e:
            self.logger.error(f"Error scanning UDP port {port}: {e}")

        finally:
            with self.progress_lock:
                self.scanned_ports += 1
                self._print_progress()

    # -------------------------------------------------------
    # Start UDP Scan
    # -------------------------------------------------------
    def scan(self):
        self.logger.info(
            f"Starting UDP scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )

        return self._run_scan(self.scan_port)