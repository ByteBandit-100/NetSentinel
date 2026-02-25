import socket
from colorama import Fore, Style
from engine.scanner.base_scanner import BaseScanner
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from engine.utils.severity_classifier import SeverityClassifier


class UDPScanner(BaseScanner):

    def __init__(self, target, start_port, end_port, threads=50, timeout=1.0, stop_event=None):
        logger = LoggerFactory.get_logger("udp_scanner", "scan_logs")
        super().__init__(target, start_port, end_port, threads, timeout, logger, stop_event)

    def scan_port(self, port: int):

        if self.stop_event.is_set():
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)

                sock.sendto(b"\x00", (self.target, port))

                service = ServiceMapper.get_service_name(port)
                banner_text = None
                status = "open|filtered"

                try:
                    data, _ = sock.recvfrom(1024)
                    banner_text = data.decode(errors="ignore").strip()[:200]
                    status = "open"
                except socket.timeout:
                    pass
                except ConnectionResetError:
                    return

                severity = SeverityClassifier.classify(port, banner_text)

                with self.result_lock:
                    print(f"{Fore.YELLOW}[{status.upper()}] UDP Port {port} | Service: {service}{Style.RESET_ALL}")

                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner_text,
                        "severity": severity,
                        "status": status
                    })

        except Exception:
            pass

        finally:
            if not self.stop_event.is_set():
                with self.progress_lock:
                    self.scanned_ports += 1
                    self._print_progress()

    def scan(self):
        self.logger.info(
            f"Starting UDP scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )
        return self._run_scan(self.scan_port)