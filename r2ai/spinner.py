import itertools
import threading
import time
import sys

class Spinner:
    def __init__(self, message="Loading...", delay=0.1):
        self.spinner = itertools.cycle([
            "\033[1;31m⠋\033[0m", "\033[1;32m⠙\033[0m", "\033[1;33m⠹\033[0m", "\033[1;34m⠸\033[0m",
            "\033[1;35m⠼\033[0m", "\033[1;36m⠴\033[0m", "\033[1;37m⠦\033[0m", "\033[1;31m⠧\033[0m",
            "\033[1;32m⠇\033[0m", "\033[1;33m⠏\033[0m"
        ])
        self.message = message
        self.delay = delay
        self.running = False
        self.thread = None
        self.start_time = None

    def start(self):
        """Start the spinner in a separate thread."""
        self.running = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def _spin(self):
        """Spin the spinner while running is True."""
        while self.running:
            elapsed_time = time.time() - self.start_time
            sys.stdout.write(f"\r{self.message} {next(self.spinner)} {elapsed_time:.1f}s")
            sys.stdout.flush()
            time.sleep(self.delay)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 20) + '\r')  # Clear the line
        sys.stdout.flush()

    def stop(self):
        """Stop the spinner."""
        self.running = False
        if self.thread is not None:
            self.thread.join()

spinner = Spinner("")