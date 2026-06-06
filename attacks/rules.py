import datetime
import multiprocessing
import os
from typing import Iterator, List, Optional

from attacks.wordlist import wordlist_producer
from utils.crypto import verify_password
from utils.data_downloader import download_rockyou_wordlist


def _leet_substitute(word: str) -> str:
    TABLE = str.maketrans("aeiot", "43107")
    return word.translate(TABLE)


BUILTIN_RULES = {
    "noop":           lambda w: [w],
    "lower":          lambda w: [w.lower()],
    "upper":          lambda w: [w.upper()],
    "capitalize":     lambda w: [w.capitalize()],
    "reverse":        lambda w: [w[::-1]],
    "double":         lambda w: [w + w],
    "toggle_case":    lambda w: [w.swapcase()],
    "leet":           lambda w: [_leet_substitute(w.lower())],
    "append_digits":  lambda w: [w + str(d) for d in range(10)],
    "prepend_digits": lambda w: [str(d) + w for d in range(10)],
    "append_year":    lambda w: [w + str(y) for y in range(2000, datetime.date.today().year + 1)],
    "append_special": lambda w: [w + s for s in ["!", "!!", "@", "#", "123", "1!", "!@#", "?"]],
}

RULE_SETS = {
    "basic":   ["noop", "lower", "upper", "capitalize", "reverse", "toggle_case"],
    "numbers": ["append_digits", "prepend_digits", "append_year"],
    "leet":    ["leet"],
    "special": ["append_special"],
    "all":     list(BUILTIN_RULES.keys()),
}


def apply_rules(word: str, rule_names: List[str]) -> Iterator[str]:
    """Yield unique candidates by applying named rules to word.

    Rules use a two-level composition: each rule is first applied directly to
    word to create first-level candidates, then all rules are applied again to
    those first-level candidates. This can produce O(rules^2) candidates per
    word; with rule_set="all" (12 rules), each word yields up to about 144
    candidates before deduplication.

    This breadth is intentional for thoroughness. Self-inverse rules (e.g.
    reverse, toggle_case) may therefore re-emit the original word as a
    second-level candidate, and duplicates are filtered before yielding.
    """
    seen: set = set()

    # Single-rule application
    first_level: List[str] = []
    for name in rule_names:
        fn = BUILTIN_RULES.get(name)
        if fn is None:
            continue
        for candidate in fn(word):
            if candidate and candidate not in seen:
                seen.add(candidate)
                first_level.append(candidate)
                yield candidate

    # Two-level composition: apply all rules to first-level results
    for intermediate in first_level:
        for name in rule_names:
            fn = BUILTIN_RULES.get(name)
            if fn is None:
                continue
            for candidate in fn(intermediate):
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    yield candidate


class RuleBasedAttack:
    """Applies rule mutations to each wordlist entry, then tests against a hash."""

    def __init__(
        self,
        wordlist_path: str,
        hash_type: str,
        rule_set: str = "all",
        max_processes: int = 4,
    ):
        if wordlist_path == "data/rockyou.txt" and not os.path.exists(wordlist_path):
            download_rockyou_wordlist()
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(
                f"Wordlist not found: '{wordlist_path}'. "
                "Download a wordlist (e.g. rockyou.txt) into the data/ directory."
            )
        self.wordlist_path = wordlist_path
        self.hash_type = hash_type
        self.rule_names: List[str] = RULE_SETS.get(rule_set, RULE_SETS["all"])
        self.max_processes = max_processes

    def _producer(self, word_queue: multiprocessing.Queue):
        wordlist_producer(self.wordlist_path, word_queue, 500, self.max_processes)

    def candidate_count(self) -> str:
        with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
        estimated = line_count * len(self.rule_names) * 5
        return f"~{estimated} (estimated)"

    def _consumer(
        self,
        word_queue: multiprocessing.Queue,
        target_hash: str,
        result_queue: multiprocessing.Queue,
    ):
        while True:
            batch = word_queue.get()
            if batch is None:
                break
            for word in batch:
                for candidate in apply_rules(word, self.rule_names):
                    if verify_password(candidate, target_hash, self.hash_type):
                        result_queue.put(candidate)
                        return
        result_queue.put(None)

    def crack(self, target_hash: str) -> Optional[str]:
        print(f"Starting rule-based attack on {self.hash_type} hash")
        print(f"Wordlist: {self.wordlist_path}")
        print(f"Rules: {self.rule_names}")
        print(f"Using {self.max_processes} processes")

        word_queue: multiprocessing.Queue = multiprocessing.Queue(maxsize=5000)
        result_queue: multiprocessing.Queue = multiprocessing.Queue()

        producer = multiprocessing.Process(target=self._producer, args=(word_queue,), daemon=True)
        producer.start()

        consumers = [
            multiprocessing.Process(
                target=self._consumer,
                args=(word_queue, target_hash, result_queue),
                daemon=True,
            )
            for _ in range(self.max_processes)
        ]
        for c in consumers:
            c.start()

        found: Optional[str] = None
        finished = 0
        try:
            while finished < self.max_processes and found is None:
                result = result_queue.get()
                if result is not None:
                    found = result
                    for c in consumers:
                        c.terminate()
                    producer.terminate()
                finished += 1
        except KeyboardInterrupt:
            for c in consumers:
                c.terminate()
            producer.terminate()
            raise

        return found
