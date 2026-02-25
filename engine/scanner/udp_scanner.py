import socket
import time
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

                from engine.vuln.vuln_engine import VulnerabilityEngine

                version = None  # unless you detect one
                vulns = VulnerabilityEngine.analyze(service, version, port, banner_text)

                with self.result_lock:
                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "banner": banner_text,
                        "severity": severity,
                        "status": status,
                        "vulnerabilities": vulns
                    })

        except Exception:
            pass

        finally:
            # 🔥 THIS IS THE MISSING PART
            if not self.stop_event.is_set():
                with self.progress_lock:
                    self.scanned_ports += 1
                    self._print_progress()

    def scan(self):
        self.logger.info(
            f"Starting UDP scan on {self.target} "
            f"from {self.start_port} to {self.end_port}"
        )

        start_time = time.time()
        results = self._run_scan(self.scan_port)
        end_time = time.time()

        scan_time = round(end_time - start_time, 2)

        print("--------------------------------------------------")
        print(f"{'PORT':<9}{'STATE':<8}\t{'SERVICE':<10}\t{'RISK'}")

        for port_info in sorted(results, key=lambda x: x["port"]):
            print(f"{str(port_info['port']) + '/udp':<9}"
                  f"{port_info['status']:<15}"
                  f"{port_info['service']:<16}"
                  f"{port_info['severity']}")
            if port_info.get("vulnerabilities"):
                for vuln in port_info["vulnerabilities"]:
                    print(f"    ↳ {vuln['id']} | {vuln['name']} | {vuln['severity']}")

        print("--------------------------------------------------")
        print(f"Scan completed in {scan_time} seconds")
        print(f"Total Open Ports: {len(results)}\n")

        return results