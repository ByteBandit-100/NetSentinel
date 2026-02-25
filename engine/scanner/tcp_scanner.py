import socket
import time
from engine.scanner.base_scanner import BaseScanner
from engine.core.logger import LoggerFactory
from engine.utils.service_mapper import ServiceMapper
from engine.utils.severity_classifier import SeverityClassifier
from engine.utils.version_detector import VersionDetector

class TCPScanner(BaseScanner):

    def __init__(self, target, start_port, end_port, threads=50, timeout=0.5, stop_event=None):
        logger = LoggerFactory.get_logger("tcp_scanner", "scan_logs")
        super().__init__(target, start_port, end_port, threads, timeout, logger, stop_event)

    def scan_port(self, port: int):

        if self.stop_event.is_set():
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))

                if result != 0:
                    return

                service = ServiceMapper.get_service_name(port)
                banner_text = None

                try:
                    if port in [80, 8080, 8000, 443]:
                        try:
                            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
                        except:
                            pass

                    banner = sock.recv(1024)
                    if banner:
                        banner_text = banner[:200]
                except:
                    pass

                version = VersionDetector.detect(banner_text)
                severity = SeverityClassifier.classify(port, banner_text)

                from engine.vuln.vuln_engine import VulnerabilityEngine

                vulns = VulnerabilityEngine.analyze(service, version, port, banner_text)

                with self.result_lock:
                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "banner": banner_text,
                        "severity": severity,
                        "status": "open",
                        "vulnerabilities": vulns
                    })

        except Exception:
            pass

        finally:
            if not self.stop_event.is_set():
                with self.progress_lock:
                    self.scanned_ports += 1
                    self._print_progress()

    def scan(self):

        start_time = time.time()
        results = self._run_scan(self.scan_port)
        end_time = time.time()

        scan_time = round(end_time - start_time, 2)

        print(f"\nHost Scan Summary: {self.target}")
        print("---------------------------------------------------------")

        if not results:
            print("\t\tNO PORTS OPENED")
        else:
            print(f"{'PORT':<9}{'STATE':<8} {'SERVICE':<15}{'VERSION':<20}{'RISK'}")
            for port_info in sorted(results, key=lambda x: x["port"]):
                version = port_info.get("version") or "-"
                print(
                    f"{str(port_info['port']) + '/tcp':<9}"
                    f"{'OPEN':<9}"
                    f"{port_info['service']:<15}"
                    f"{version:<20}"
                    f"{port_info['severity']}"
                )
                if port_info.get("vulnerabilities"):
                    for vuln in port_info["vulnerabilities"]:
                        print(f"    ↳ {vuln['id']} | {vuln['name']} | {vuln['severity']}")

        print("---------------------------------------------------------")
        print(f"Scan completed in {scan_time} seconds")
        print(f"Total Open Ports: {len(results)}\n")

        return results