import os
import requests
from tqdm import tqdm


def download_file(url: str, destination_path: str):
    """
    Downloads a file from a given URL to a specified destination path with a progress bar.
    """
    response = requests.get(url, stream=True, allow_redirects=True, timeout=(10, 30))
    response.raise_for_status()  # Raise an exception for bad status codes

    total_size = int(response.headers.get("content-length", 0))

    os.makedirs(os.path.dirname(destination_path), exist_ok=True)

    with tqdm(
        total=total_size, unit="B", unit_scale=True, desc=url.split("/")[-1]
    ) as pbar:
        with open(destination_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                pbar.update(len(chunk))
    print(f"\nDownloaded '{url.split('/')[-1]}' to '{destination_path}'")


def download_rockyou_wordlist():
    """
    Downloads the rockyou.txt wordlist if it doesn't already exist.
    """
    wordlist_path = os.path.join("data", "rockyou.txt")
    download_url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

    if os.path.exists(wordlist_path):
        print(f"'{wordlist_path}' already exists. Skipping download.")
        return

    print(f"Downloading '{wordlist_path}'...")
    try:
        download_file(download_url, wordlist_path)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading '{wordlist_path}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    download_rockyou_wordlist()
