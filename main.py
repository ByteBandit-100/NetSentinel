import argparse
import ipaddress
import sys
import time
from config import APP_NAME, VERSION
from engine.core.logger import LoggerFactory
from engine.core.validator import InputValidator
from engine.scanner.tcp_scanner import TCPScanner
from engine.scanner.udp_scanner import UDPScanner
from engine.export.json_exporter import JSONExporter
from engine.export.html_exporter import HTMLExporter
from engine.scanner.host_discovery import HostDiscovery
from colorama import init
init(autoreset=True)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetSentinel - Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "--compare",
        help="Path to previous JSON report to compare with"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Start port (default: 1)"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="End port (default: 1024)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)"
    )

    parser.add_argument(
        "--scan",
        choices=["tcp", "udp"],
        default="tcp",
        help="Type of scan: tcp or udp"
    )

    parser.add_argument(
        "--speed",
        choices=["stealth", "normal", "aggressive"],
        default="normal",
        help="Scan speed profile"
    )

    return parser.parse_args()

def resolve_speed_profile(speed: str, custom_threads: int):
    """
    Returns (threads, delay) based on speed profile.
    If user provides custom thread count, it overrides profile threads.
    """

    profiles = {
        "stealth": {"threads": 10, "delay": 0.2},
        "normal": {"threads": 50, "delay": 0.05},
        "aggressive": {"threads": 200, "delay": 0}
    }

    profile = profiles[speed]

    # If user manually provided threads, override profile threads
    threads = custom_threads if custom_threads else profile["threads"]

    return threads, profile["delay"]

def main():
    import threading
    stop_event = threading.Event()
    logger = LoggerFactory.get_logger("app", "scan_logs")

    print(f"{APP_NAME} v{VERSION} starting...\n")
    logger.info("Application started.")

    try:
        args = parse_arguments()

        # -----------------------------
        # 1️⃣ Validate & Expand Targets
        # -----------------------------
        import socket

        try:
            if "/" in args.target:
                # CIDR handling
                network = ipaddress.ip_network(args.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]

            else:
                try:
                    # Try direct IP validation first
                    InputValidator.validate_ip(args.target)
                    targets = [args.target]

                except Exception:
                    # If not IP → try DNS resolution
                    print(f"Resolving domain: {args.target} ...")
                    resolved_ip = socket.gethostbyname(args.target)
                    print(f"Resolved to: {resolved_ip}")
                    targets = [resolved_ip]

        except Exception:
            raise ValueError("Invalid IP address, domain, or CIDR range.")

        # -----------------------------
        # 2️⃣ Host Discovery
        # -----------------------------
        print("\nPerforming Host Discovery...")
        print("-----------------------------------------------")

        alive_targets = HostDiscovery.discover_hosts(
            targets,
            threads=200 if args.speed == "aggressive" else 100,
            timeout=0.5
        )

        if not alive_targets:
            print("No live hosts found.")
            return

        for host in alive_targets:
            print(f"Host {host:<15}   →  UP")

        print("-----------------------------------------------")
        print(f"Total Live Hosts: {len(alive_targets)}\n")

        targets = alive_targets

        logger.info(
            f"Scan requested | Type={args.scan} | "
            f"Targets={len(targets)} | "
            f"Ports={args.start}-{args.end} | "
            f"Threads={args.threads} | "
            f"Timeout={args.timeout}"
        )

        # -----------------------------
        # 3️⃣ Start Scan Timer
        # -----------------------------
        start_time = time.time()

        all_results = []

        # -----------------------------
        # 4️⃣ Scanning Loop
        # -----------------------------
        for target in targets:

            if stop_event.is_set():
                print("\nGlobal stop detected. Exiting network scan...")
                break

            print(f"Scanning Host: {target}")
            logger.info(f"Scanning host: {target}")
            # Resolve speed profile once per host
            threads, delay = resolve_speed_profile(args.speed, args.threads)

            if args.scan == "tcp":
                scanner = TCPScanner(
                    target=target,
                    start_port=args.start,
                    end_port=args.end,
                    threads=threads,
                    timeout=args.timeout,
                    stop_event = stop_event
                )
            else:
                scanner = UDPScanner(
                    target=target,
                    start_port=args.start,
                    end_port=args.end,
                    threads=threads,
                    timeout=args.timeout,
                    stop_event=stop_event
                )

            scanner.delay = delay
            try:
                results = scanner.scan()
            except KeyboardInterrupt:
                print("\nFull scan cancelled by user.")
                stop_event.set()  # 🔥 signal all threads
                sys.exit(0)

            all_results.append({
                "target": target,
                "open_ports": results
            })

        # -----------------------------
        # 5️⃣ End Timer
        # -----------------------------
        end_time = time.time()
        total_time = round(end_time - start_time, 2)

        logger.info(f"Scan completed in {total_time} seconds.")

        # -----------------------------
        # 6️⃣ Prepare Report Data
        # -----------------------------
        report_data = {
            "scan_type": args.scan,
            "targets_scanned": len(targets),
            "results": all_results,
            "start_port": args.start,
            "end_port": args.end,
            "scan_time": total_time
        }

        # -----------------------------
        # 7️⃣ Export Reports
        # -----------------------------
        report_path = JSONExporter.export(report_data, args.target)
        html_path = HTMLExporter.export(report_data, args.target)

        print(f"\nHTML report saved to: {html_path}")
        print(f"Report saved to: {report_path}")

        logger.info(f"Reports exported successfully.")

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        print(f"[ERROR] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        sys.exit(0)