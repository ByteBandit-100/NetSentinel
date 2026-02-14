import argparse
import sys
import time
from config import APP_NAME, VERSION
from engine.core.logger import LoggerFactory
from engine.core.validator import InputValidator
from engine.scanner.tcp_scanner import TCPScanner
from engine.export.json_exporter import JSONExporter



def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetSentinel - Multithreaded TCP Port Scanner"
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

    return parser.parse_args()


def main():
    logger = LoggerFactory.get_logger("app", "scan_logs")

    print(f"{APP_NAME} v{VERSION} starting...\n")
    logger.info("Application started.")

    try:
        args = parse_arguments()

        # Validate input
        InputValidator.validate_ip(args.target)
        InputValidator.validate_port_range(args.start, args.end)

        logger.info(
            f"Scan requested: Target={args.target}, "
            f"Ports={args.start}-{args.end}, "
            f"Threads={args.threads}"
        )

        scanner = TCPScanner(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            threads=args.threads
        )

        start_time = time.time()

        open_ports_list = scanner.scan()  # ✅ capture results

        end_time = time.time()
        total_time = round(end_time - start_time, 2)

        total_ports = args.end - args.start + 1

        logger.info("Scan completed successfully.")

        report_data = {
            "target": args.target,
            "start_port": args.start,
            "end_port": args.end,
            "open_ports": open_ports_list,
            "total_scanned": total_ports,
            "scan_time": total_time
        }

        report_path = JSONExporter.export(report_data, args.target)

        print(f"\nReport saved to: {report_path}")
        logger.info(f"Report exported to {report_path}")


    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        print(f"[ERROR] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
