import multiprocessing
from typing import List

from tqdm import tqdm


def wordlist_producer(
    path: str,
    queue: multiprocessing.Queue,
    batch_size: int,
    num_consumers: int,
) -> None:
    """Read wordlist in batches, send to queue, then send num_consumers None sentinels."""
    batch: List[str] = []
    desc = "Rule attack - reading wordlist" if batch_size == 500 else "Reading wordlist"

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            with tqdm(desc=desc, unit="line", miniters=10000) as pbar:
                for line in f:
                    word = line.strip()
                    if word:
                        batch.append(word)
                    if len(batch) >= batch_size:
                        queue.put(batch)
                        batch = []
                    pbar.update(1)

        if batch:
            queue.put(batch)
    except Exception as e:
        print(f"Error reading wordlist: {e}")
    finally:
        for _ in range(num_consumers):
            queue.put(None)
