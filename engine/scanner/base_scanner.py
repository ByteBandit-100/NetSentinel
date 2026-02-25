import threading
import time
from engine.scanner.thread_pool import ThreadPoolManager


class BaseScanner:

    def __init__(self, target, start_port, end_port, threads, timeout, logger, stop_event=None):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.logger = logger

        self.open_ports = []
        self.scanned_ports = 0
        self.total_ports = end_port - start_port + 1

        self.result_lock = threading.Lock()
        self.progress_lock = threading.Lock()
        self.stop_event = stop_event or threading.Event()
        self.delay = 0

    # ---------------------------------------
    # Progress Printer
    # ---------------------------------------
    def _print_progress(self):
        percent = (self.scanned_ports / self.total_ports) * 100
        print(f"\rProgress: {percent:.1f}% ({self.scanned_ports}/{self.total_ports})", end="")

    # ---------------------------------------
    # Safe Delay (Interrupt Friendly)
    # ---------------------------------------
    def _safe_delay(self):
        if self.delay <= 0:
            return

        steps = int(self.delay / 0.01)
        for _ in range(steps):
            if self.stop_event.is_set():
                return
            time.sleep(0.01)

    # ---------------------------------------
    # Core Runner
    # ---------------------------------------
    def _run_scan(self, scan_function):

        ports = range(self.start_port, self.end_port + 1)
        pool = ThreadPoolManager(self.threads, self.stop_event)

        def wrapped_scan(port):
            if self.stop_event.is_set():
                return

            scan_function(port)

            if self.stop_event.is_set():
                return

            self._safe_delay()

        try:
            pool.run(wrapped_scan, ports)

        except KeyboardInterrupt:
            print("\nScan interrupted. Stopping everything...")
            self.stop_event.set()
            raise  # 🔥 VERY IMPORTANT

        print()
        return self.open_ports