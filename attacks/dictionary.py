import multiprocessing
from typing import Optional
from attacks.wordlist import wordlist_producer
from utils.crypto import verify_password
import os
from utils.data_downloader import download_rockyou_wordlist


class DictionaryAttack:
    """Multi-process dictionary attack"""

    def __init__(self, wordlist_path: str, hash_type: str, max_processes: int = 4):
        if wordlist_path == "data/rockyou.txt" and not os.path.exists(wordlist_path):
            download_rockyou_wordlist()

        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(
                f"Wordlist not found at '{wordlist_path}'. "
                "Please ensure the file exists. "
                "You may need to download a wordlist like 'rockyou.txt' and place it in the 'data' directory."
            )
        self.wordlist_path = wordlist_path
        self.hash_type = hash_type
        self.max_processes = max_processes

    def _password_producer(self, password_queue: multiprocessing.Queue):
        """Produce passwords from wordlist in batches"""
        wordlist_producer(self.wordlist_path, password_queue, 1000, self.max_processes)

    def candidate_count(self) -> int:
        with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)

    def _password_consumer(
        self, password_queue: multiprocessing.Queue, target_hash: str, result_queue: multiprocessing.Queue
    ):
        """Consume password batches and test against hash"""
        while True:
            batch = password_queue.get()

            # Check for termination signal
            if batch is None:
                break

            for password in batch:
                if verify_password(password, target_hash, self.hash_type):
                    result_queue.put(password)
                    return

        result_queue.put(None)

    def crack(self, target_hash: str) -> Optional[str]:
        """Perform dictionary attack"""
        print(f"Starting dictionary attack on {self.hash_type} hash")
        print(f"Using wordlist: {self.wordlist_path}")
        print(f"Using {self.max_processes} processes")

        password_queue = multiprocessing.Queue(maxsize=10000)
        result_queue = multiprocessing.Queue()

        # Start producer process
        producer_process = multiprocessing.Process(
            target=self._password_producer, args=(password_queue,)
        )
        producer_process.daemon = True
        producer_process.start()

        # Start consumer processes
        consumer_processes = []
        for _ in range(self.max_processes):
            process = multiprocessing.Process(
                target=self._password_consumer,
                args=(password_queue, target_hash, result_queue),
            )
            process.daemon = True
            process.start()
            consumer_processes.append(process)

        # Wait for a result
        found_password = None
        results_received = 0

        try:
            while results_received < self.max_processes and found_password is None:
                result = result_queue.get()
                if result is not None:
                    found_password = result
                    # Terminate other processes as soon as we find it
                    for p in consumer_processes:
                        p.terminate()
                    producer_process.terminate()
                results_received += 1
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            for p in consumer_processes:
                p.terminate()
            producer_process.terminate()
            raise

        return found_password
