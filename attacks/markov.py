import random
import json
import multiprocessing
import os
from typing import Dict, List, Set, Optional, Iterator
from collections import Counter
from utils.crypto import hash_password, verify_password
from utils.data_downloader import download_rockyou_wordlist


class MarkovModel:
    """Markov chain model for password generation with serialization support"""

    def __init__(self, order: int = 3):
        self.order = order
        self.model: Dict[str, Dict[str, int]] = {}
        self.start_states: Dict[str, int] = {}

    def train(self, passwords, max_training_samples: int = 100000):
        """Train the Markov model on an iterator of passwords with a sample limit"""
        from tqdm import tqdm
        print(f"Training Markov model (max samples: {max_training_samples})...")

        count = 0
        with tqdm(total=max_training_samples, desc="Training", unit="pwd") as pbar:
            for password in passwords:
                password = password.strip()
                if not password or len(password) < self.order:
                    continue

                start = password[: self.order]
                self.start_states[start] = self.start_states.get(start, 0) + 1

                for i in range(len(password) - self.order):
                    state = password[i : i + self.order]
                    next_char = password[i + self.order]
                    if state not in self.model:
                        self.model[state] = {}
                    self.model[state][next_char] = self.model[state].get(next_char, 0) + 1

                count += 1
                pbar.update(1)
                if count >= max_training_samples:
                    break

        print(
            f"Model trained with {len(self.model)} states and {len(self.start_states)} start states"
        )

    def train_from_file(self, filepath: str, max_training_samples: int = 100000):
        """Train Markov model from a file using streaming"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Training file not found: {filepath}")
            
        def file_iterator():
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line
        
        self.train(file_iterator(), max_training_samples)

    def generate_password(self, max_length: int = 20) -> str:
        """Generate a password using the Markov model"""
        if not self.start_states:
            return ""

        # Choose random start state based on frequency
        states = list(self.start_states.keys())
        weights = list(self.start_states.values())
        state = random.choices(states, weights=weights)[0]
        password = state

        while len(password) < max_length:
            if state not in self.model or not self.model[state]:
                break

            # Choose next character based on frequency
            chars = list(self.model[state].keys())
            char_weights = list(self.model[state].values())
            next_char = random.choices(chars, weights=char_weights)[0]
            password += next_char

            # Update state (slide window)
            state = password[-self.order :]

        return password

    def save_model(self, filepath: str):
        """Save the trained model to a file"""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "order": self.order,
                    "model": self.model,
                    "start_states": self.start_states,
                },
                f,
            )
        print(f"Model saved to {filepath}")

    def load_model(self, filepath: str):
        """Load a trained model from a file"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.order = data["order"]
            self.model = data["model"]
            self.start_states = data["start_states"]
        print(f"Model loaded from {filepath}")


class AdvancedPasswordGenerator:
    """Consolidated password generator using Markov models"""
    
    def __init__(self, training_file: Optional[str] = None):
        self.model = MarkovModel(order=3)
        self.trained = False
        if training_file:
            self.train_from_file(training_file)

    def train_from_file(self, filepath: str):
        self.model.train_from_file(filepath)
        self.trained = True

    def generate_passwords(self, count: int = 10, min_length: int = 8, max_length: int = 16) -> List[str]:
        if not self.trained:
            raise ValueError("Model must be trained before generating passwords")

        passwords: Set[str] = set()
        attempts = 0
        max_attempts = count * 20

        while len(passwords) < count and attempts < max_attempts:
            pwd = self.model.generate_password(max_length)
            if pwd and min_length <= len(pwd) <= max_length:
                passwords.add(pwd)
            attempts += 1

        return list(passwords)


class MarkovAttack:
    """Markov chain-based password attack using multiprocessing"""

    def __init__(
        self,
        training_file: str,
        hash_type: str,
        max_processes: int = 4,
        max_passwords: int = 100000,
    ):
        if training_file == "data/rockyou.txt" and not os.path.exists(training_file):
            download_rockyou_wordlist()
        
        self.training_file = training_file
        self.hash_type = hash_type
        self.max_processes = max_processes
        self.max_passwords = max_passwords
        self.model = MarkovModel(order=3)
        self.trained = False

    def train_model(self):
        """Train the Markov model on the provided file"""
        try:
            self.model.train_from_file(self.training_file)
            self.trained = True
        except Exception as e:
            print(f"Error training Markov model: {e}")
            raise

    def candidate_count(self) -> int:
        return self.max_passwords

    def _worker(self, target_hash: str, num_passwords: int, result_queue: multiprocessing.Queue):
        """Worker process to generate and test passwords"""
        for _ in range(num_passwords):
            password = self.model.generate_password()
            if verify_password(password, target_hash, self.hash_type):
                result_queue.put(password)
                return
        result_queue.put(None)

    def crack(self, target_hash: str) -> Optional[str]:
        """Attempt to crack the hash using Markov-generated passwords"""
        if not self.trained:
            self.train_model()

        print(f"Starting Markov attack on {self.hash_type} hash")
        print(f"Generating up to {self.max_passwords} password candidates...")
        print(f"Using {self.max_processes} processes")

        result_queue = multiprocessing.Queue()
        passwords_per_process = self.max_passwords // self.max_processes
        
        processes = []
        for _ in range(self.max_processes):
            p = multiprocessing.Process(
                target=self._worker,
                args=(target_hash, passwords_per_process, result_queue)
            )
            p.daemon = True
            p.start()
            processes.append(p)

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

        return found_password
