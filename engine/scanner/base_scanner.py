import time
import threading
from engine.scanner.thread_pool import ThreadPoolManager


class BaseScanner:

    def __init__(self, target, start_port, end_port, threads, timeout, logger):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.logger = logger
        self.delay = 0
        self.total_ports = end_port - start_port + 1
        self.scanned_ports = 0
        self.open_ports = []

        self.progress_lock = threading.Lock()
        self.result_lock = threading.Lock()

    # -----------------------------------------
    # Progress Bar
    # -----------------------------------------
    def _print_progress(self):
        percent = self.scanned_ports / self.total_ports
        bar_length = 30
        filled_length = int(bar_length * percent)

        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        print(
            f"\r[{bar}] "
            f"{percent * 100:.0f}% "
            f"({self.scanned_ports}/{self.total_ports}) "
            f"| Open: {len(self.open_ports)}",
            end=""
        )

    # -----------------------------------------
    # Shared Scan Engine
    # -----------------------------------------
    def _run_scan(self, scan_function):
        print(f"\nScanning {self.target} with {self.threads} threads...\n")

        start_time = time.time()

        pool = ThreadPoolManager(self.threads)
        ports = range(self.start_port, self.end_port + 1)

        def delayed_scan(port):
            if self.delay > 0:
                time.sleep(self.delay)
            scan_function(port)

        pool.run(delayed_scan, ports)
        duration = round(time.time() - start_time, 2)

        print()
        print("\nScan Summary")
        print("---------------------------------")
        print(f"Target: {self.target}")
        print(f"Ports scanned: {self.scanned_ports}")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Time taken: {duration} seconds.")

        return self.open_ports