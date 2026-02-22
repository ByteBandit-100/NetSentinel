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
    logger = LoggerFactory.get_logger("app", "scan_logs")

    print(f"{APP_NAME} v{VERSION} starting...\n")
    logger.info("Application started.")

    try:
        args = parse_arguments()

        # -----------------------------
        # 1️⃣ Validate & Expand Targets
        # -----------------------------
        try:
            if "/" in args.target:
                network = ipaddress.ip_network(args.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            else:
                InputValidator.validate_ip(args.target)
                targets = [args.target]
        except Exception:
            raise ValueError("Invalid IP address or CIDR range.")

        # -----------------------------
        # 2️⃣ Host Discovery
        # -----------------------------
        print("\nPerforming host discovery...")
        alive_targets = []

        for ip in targets:
            if HostDiscovery.is_host_alive(ip):
                print(f"[+] Host Alive: {ip}")
                logger.info(f"Host alive: {ip}")
                alive_targets.append(ip)

        if not alive_targets:
            print("No live hosts found.")
            logger.warning("No live hosts detected.")
            return

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
            print(f"\nScanning Host: {target}")
            logger.info(f"Scanning host: {target}")
            # Resolve speed profile once per host
            threads, delay = resolve_speed_profile(args.speed, args.threads)

            if args.scan == "tcp":
                scanner = TCPScanner(
                    target=target,
                    start_port=args.start,
                    end_port=args.end,
                    threads=threads,
                    timeout=args.timeout
                )
            else:
                scanner = UDPScanner(
                    target=target,
                    start_port=args.start,
                    end_port=args.end,
                    threads=threads,
                    timeout=args.timeout
                )

            scanner.delay = delay
            results = scanner.scan()

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
    main()
