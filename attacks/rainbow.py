import os
import json
from typing import Optional
from utils.crypto import hash_password


class RainbowAttack:
    """Rainbow table attack implementation"""

    def __init__(self, rainbow_table_path: Optional[str] = None):
        self.rainbow_table_path = rainbow_table_path
        self.rainbow_table = {}

        if rainbow_table_path and os.path.exists(rainbow_table_path):
            self.load_rainbow_table(rainbow_table_path)
        elif rainbow_table_path:
            print(f"Rainbow table not found: {rainbow_table_path}")

    def load_rainbow_table(self, file_path: str):
        """Load rainbow table from file"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                try:
                    table = json.load(f)
                    if isinstance(table, dict):
                        self.rainbow_table = table
                    else:
                        raise ValueError("Rainbow JSON table must be an object")
                except json.JSONDecodeError:
                    f.seek(0)
                    for line in f:
                        if ":" in line:
                            hash_val, password = line.strip().split(":", 1)
                            self.rainbow_table[hash_val] = password
            print(f"Loaded {len(self.rainbow_table)} entries from rainbow table")
        except Exception as e:
            print(f"Error loading rainbow table: {e}")
            self.rainbow_table = {}

    def candidate_count(self) -> int:
        if not self.rainbow_table_path:
            return 0
        try:
            with open(self.rainbow_table_path, "r", encoding="utf-8") as f:
                table = json.load(f)
            if isinstance(table, dict):
                return len(table)
        except (json.JSONDecodeError, OSError):
            pass
        with open(self.rainbow_table_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)

    def generate_rainbow_table(
        self, wordlist_path: str, output_path: str, hash_type: str = "md5"
    ):
        """Generate a rainbow table from a wordlist"""
        from tqdm import tqdm
        print(f"Generating rainbow table for {hash_type}...")
        rainbow_table = {}

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in tqdm(f, desc=f"Hashing ({hash_type})", unit="line"):
                    password = line.strip()
                    if password:
                        hash_val = hash_password(password, hash_type)
                        rainbow_table[hash_val] = password

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(rainbow_table, f)

            print(f"Rainbow table generated with {len(rainbow_table)} entries")
            self.rainbow_table = rainbow_table

        except Exception as e:
            print(f"Error generating rainbow table: {e}")

    def crack(self, target_hash: str) -> Optional[str]:
        """Lookup hash in rainbow table"""
        if not self.rainbow_table:
            print("No rainbow table loaded. Use --rainbow-table to specify a file.")
            return None

        return self.rainbow_table.get(target_hash)
