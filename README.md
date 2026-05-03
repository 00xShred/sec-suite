# SEC-SUITE

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Poetry](https://img.shields.io/badge/package-poetry-blueviolet)](https://python-poetry.org/)

A security toolkit for password auditing and network reconnaissance. Provides both an interactive CLI and direct terminal commands.

## Features

| Category | Capabilities |
| :--- | :--- |
| **Password Attacks** | Markov Chain (probabilistic), Brute Force (configurable), Dictionary (multi-process), Rainbow Table |
| **Performance** | Multi-processing across all attack modules, optimized password batching |
| **Hash Support** | Argon2, Bcrypt, Scrypt, SHA-256/512, MD5, and more with auto-detection |
| **Network** | SYN Port Scanner (requires root), service discovery, CIDR support |
| **Password Generation** | Markov model-trained generator for realistic password lists |
| **Utilities** | Encoding/decoding (Base64, Hex, URL, HTML), password strength analyzer |

## Setup

```bash
git clone https://github.com/gab-dev-7/sec-suite.git
cd sec-suite
poetry install
poetry shell
```

## Interactive Mode

```bash
python run.py
```

Menu-driven access to all features: password cracking, network scanning, password generation, hash analysis, and encoding utilities.

## CLI Usage

Ensure you have run `poetry shell` first.

### Password Cracking

```bash
# Dictionary attack
python main.py crack -t <HASH> -a sha256 -m dictionary

# Markov chain attack
python main.py crack -t <HASH> -a md5 -m markov --max-passwords 50000

# Brute force (lowercase + digits, length 4-6)
python main.py crack -t <HASH> -a sha1 -m bruteforce --charset "ld" --min-length 4 --max-length 6

# Rainbow table lookup
python main.py crack -t <HASH> -m rainbow --rainbow-table my_table.json
```

### Network Scanning

Requires root privileges (SYN scan uses raw sockets).

```bash
# Scan a single host
sudo python main.py scan -t 192.168.1.5 -p 1-1000 --threads 50

# Scan a subnet
sudo python main.py scan -t 192.168.1.0/24 -p 22,80,443
```

### Utilities

```bash
python main.py analyze -p "Sup3rS3cr3t!"
python main.py encode -d "hello world" -e base64 -o encode
python main.py encode -d "hello%20world" -e url -o decode
```

## Project Structure

```
sec-suite/
├── attacks/     # Modular attack implementations
├── tools/       # Network scanner and encoders
├── utils/       # Core logic (hash detection, crypto)
├── data/        # Wordlists (auto-downloads rockyou.txt)
└── main.py      # CLI entry point
```

Custom wordlists: place in `data/` and use `-w data/my_custom_list.txt`.

## Legal

For educational purposes, authorized security research, and personal auditing only. Do not use against systems you don't own or lack explicit permission to test.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit and push your changes
4. Open a Pull Request
