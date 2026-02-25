import socket
from colorama import Fore, Style
from engine.scanner.base_scanner import BaseScanner
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from engine.utils.severity_classifier import SeverityClassifier


class TCPScanner(BaseScanner):

    def __init__(self, target, start_port, end_port, threads=50, timeout=0.5, stop_event=None):
        logger = LoggerFactory.get_logger("tcp_scanner", "scan_logs")
        super().__init__(target, start_port, end_port, threads, timeout, logger, stop_event)

    def scan_port(self, port: int):

        if self.stop_event.is_set():
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)

                result = sock.connect_ex((self.target, port))

                if self.stop_event.is_set():
                    sock.close()
                    return

                if result != 0:
                    return

                service = ServiceMapper.get_service_name(port)
                banner_text = None

                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    if banner:
                        banner_text = banner[:200]
                except:
                    pass

                severity = SeverityClassifier.classify(port, banner_text)

                with self.result_lock:
                    print(f"{Fore.GREEN}[OPEN] TCP Port {port} | Service: {service}{Style.RESET_ALL}")

                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner_text,
                        "severity": severity,
                        "status": "open"
                    })
                sock.close()

        except Exception:
            pass

        finally:
            if not self.stop_event.is_set():
                with self.progress_lock:
                    self.scanned_ports += 1
                    self._print_progress()

    def scan(self):
        self.logger.info(
            f"Starting TCP scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )
        return self._run_scan(self.scan_port)