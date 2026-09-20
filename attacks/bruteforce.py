import itertools
import multiprocessing
import string
from typing import Optional, List
from utils.crypto import verify_password


class BruteForceAttack:
    """Multi-process brute force password attack"""

    # Character sets
    CHAR_SETS = {
        "l": string.ascii_lowercase,
        "u": string.ascii_uppercase,
        "d": string.digits,
        "s": string.punctuation,
    }

    def __init__(
        self,
        hash_type: str,
        charset: str = "lud",
        min_length: int = 1,
        max_length: int = 8,
        max_processes: int = 4,
    ):
        self.hash_type = hash_type
        self.charset = self._build_charset(charset)
        self.min_length = min_length
        self.max_length = max_length
        self.max_processes = max_processes

        if self.min_length < 1:
            raise ValueError("min_length must be at least 1")
        if self.max_length < self.min_length:
            raise ValueError("max_length must be greater than or equal to min_length")
        if not self.charset:
            raise ValueError("charset must include at least one known character set")

    def _build_charset(self, charset_spec: str) -> str:
        """Build character set from specification string"""
        charset = ""
        for char in charset_spec:
            if char in self.CHAR_SETS:
                charset += self.CHAR_SETS[char]
        return "".join(sorted(set(charset)))  # Remove duplicates

    def _charset_chunks(self) -> List[List[str]]:
        charset_list = list(self.charset)
        worker_count = min(self.max_processes, len(charset_list))
        chunk_size = (len(charset_list) + worker_count - 1) // worker_count
        return [charset_list[i : i + chunk_size] for i in range(0, len(charset_list), chunk_size)]

    def _worker(
        self, 
        target_hash: str, 
        length: int, 
        first_chars: List[str], 
        result_queue: multiprocessing.Queue
    ):
        """Worker process to test a subset of combinations"""
        for first_char in first_chars:
            # If length is 1, just test the first_char
            if length == 1:
                if verify_password(first_char, target_hash, self.hash_type):
                    result_queue.put(first_char)
                    return
                continue

            # For length > 1, generate combinations starting with first_char
            remaining_len = length - 1
            for combo in itertools.product(self.charset, repeat=remaining_len):
                password = first_char + "".join(combo)
                if verify_password(password, target_hash, self.hash_type):
                    result_queue.put(password)
                    return
        
        result_queue.put(None)

    def crack(self, target_hash: str) -> Optional[str]:
        """Perform brute force attack"""
        print(f"Starting brute force attack on {self.hash_type} hash")
        print(f"Character set: {self.charset}")
        print(f"Password length: {self.min_length}-{self.max_length}")
        print(f"Total combinations: {self.calculate_total_combinations()}")
        print(f"Using {self.max_processes} processes")

        for length in range(self.min_length, self.max_length + 1):
            print(f"Trying length {length}...")
            
            result_queue = multiprocessing.Queue()
            processes = []
            
            # Divide the charset among workers
            for chars_chunk in self._charset_chunks():
                p = multiprocessing.Process(
                    target=self._worker,
                    args=(target_hash, length, chars_chunk, result_queue)
                )
                p.daemon = True
                p.start()
                processes.append(p)

            # Wait for results for this length
            found_password = None
            finished_workers = 0
            
            try:
                while finished_workers < len(processes):
                    result = result_queue.get()
                    if result:
                        found_password = result
                        for p in processes:
                            p.terminate()
                        return found_password
                    finished_workers += 1
            except KeyboardInterrupt:
                for p in processes:
                    p.terminate()
                raise

        return None

    def calculate_total_combinations(self) -> int:
        """Calculate total number of possible combinations"""
        total = 0
        charset_size = len(self.charset)
        for length in range(self.min_length, self.max_length + 1):
            total += charset_size**length
        return total

    def candidate_count(self) -> int:
        return self.calculate_total_combinations()
