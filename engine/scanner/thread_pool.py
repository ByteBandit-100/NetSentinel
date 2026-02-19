from concurrent.futures import ThreadPoolExecutor

class ThreadPoolManager:
    def __init__(self, max_threads=50):
        self.max_threads = max_threads

    def run(self, func, tasks):
        """Run func on all tasks using ThreadPoolExecutor"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(func, task) for task in tasks]
            for future in futures:
                future.result()  # Wait for all to finish
