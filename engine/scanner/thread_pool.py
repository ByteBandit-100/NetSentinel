from concurrent.futures import ThreadPoolExecutor

class ThreadPoolManager:

    def __init__(self, max_workers, stop_event):
        self.max_workers = max_workers
        self.stop_event = stop_event

    def run(self, function, iterable):

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            futures = []

            for item in iterable:
                if self.stop_event.is_set():
                    break
                futures.append(executor.submit(function, item))

            try:
                for future in futures:
                    if self.stop_event.is_set():
                        break
                    future.result()

            except KeyboardInterrupt:
                self.stop_event.set()
                executor.shutdown(wait=False, cancel_futures=True)
                raise