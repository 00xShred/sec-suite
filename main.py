#!/usr/bin/env python3
"""
SEC-SUITE - Security Testing Toolkit
Author: gab-dev-7
"""

import argparse
import sys
import logging
from attacks.dictionary import DictionaryAttack
from attacks.rainbow import RainbowAttack
from attacks.markov import MarkovAttack
from attacks.bruteforce import BruteForceAttack
from utils.banner import show_banner
from utils.crypto import hash_password, identify_hash_type
from utils.password_analyzer import analyze_password_strength
from interactive_cli import main as interactive_main


def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("sec-suite.log", mode="a"),
        ],
    )


def password_cracker_mode(args):
    """Handle password cracking operations"""
    if args.attack_mode == "dictionary":
        attack = DictionaryAttack(
            wordlist_path=args.wordlist,
            hash_type=args.hash_type,
            max_processes=args.threads,
        )
    elif args.attack_mode == "markov":
        attack = MarkovAttack(
            training_file=args.wordlist,
            hash_type=args.hash_type,
            max_processes=args.threads,
            max_passwords=args.max_passwords,
        )
    elif args.attack_mode == "bruteforce":
        attack = BruteForceAttack(
            hash_type=args.hash_type,
            charset=args.charset,
            min_length=args.min_length,
            max_length=args.max_length,
            max_processes=args.threads,
        )
    elif args.attack_mode == "rainbow":
        attack = RainbowAttack(args.rainbow_table)
    else:
        print(f"Unknown attack mode: {args.attack_mode}")
        return

    # Auto-detect hash type if not specified
    hash_type = args.hash_type
    if not hash_type and args.target_hash:
        hash_type = identify_hash_type(args.target_hash)
        if hash_type:
            print(f"Auto-detected hash type: {hash_type}")
        else:
            print("Could not auto-detect hash type. Please specify with -a")
            return

    if args.target_hash:
        result = attack.crack(args.target_hash)
        if result:
            print(f"\n[+] Password found: {result}")
        else:
            print("\n[-] Password not found")
    elif args.test_password:
        hash_result = hash_password(args.test_password, hash_type)
        print(f"Hash ({hash_type}): {hash_result}")


def network_scanner_mode(args):
    """Handle network scanning operations"""
    from tools.network_scanner import NetworkScanner

    scanner = NetworkScanner(
        target=args.target, ports=args.ports, max_threads=args.threads
    )
    scanner.scan()


def encoder_mode(args):
    """Handle encoding/decoding operations"""
    from tools.encoder import encode_decode

    result = encode_decode(
        data=args.data, operation=args.operation, encoding_type=args.encoding_type
    )
    print(f"Result: {result}")


def password_analyzer_mode(args):
    """Handle password strength analysis"""
    if args.password:
        strength = analyze_password_strength(args.password)
        print(f"Password: {args.password}")
        print(f"Strength: {strength}/100")
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if password:
                        strength = analyze_password_strength(password)
                        print(f"Line {line_num}: {password} - Strength: {strength}/100")
        except FileNotFoundError:
            print(f"File not found: {args.file}")


def generate_rainbow_mode(args):
    """Handle rainbow table generation"""
    import os

    attack = RainbowAttack()
    attack.generate_rainbow_table(
        wordlist_path=args.wordlist,
        output_path=args.output,
        hash_type=args.hash_type,
    )
    if os.path.exists(args.output):
        print(f"\n[+] Rainbow table saved to: {args.output}")
    else:
        print(f"\n[-] Rainbow table was not created. Check the error above.")


def interactive_mode(args):
    """Start the interactive menu-driven interface"""
    from interactive_cli import main as interactive_main

    interactive_main()


def main():
    show_banner()

    parser = argparse.ArgumentParser(description="SEC-SUITE Security Toolkit")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Password Cracker
    cracker_parser = subparsers.add_parser("crack", help="Password cracking tools")
    cracker_parser.add_argument("-t", "--target-hash", help="Target hash to crack")
    cracker_parser.add_argument("-p", "--test-password", help="Test password hashing")
    cracker_parser.add_argument(
        "-a",
        "--hash-type",
        help="Hash algorithm",
        choices=["md5", "sha1", "sha256", "sha512", "bcrypt", "scrypt", "argon2"],
    )
    cracker_parser.add_argument(
        "-m",
        "--attack-mode",
        required=True,
        choices=["dictionary", "markov", "bruteforce", "rainbow"],
        help="Attack method",
    )
    cracker_parser.add_argument(
        "-w", "--wordlist", default="data/rockyou.txt", help="Wordlist path"
    )
    cracker_parser.add_argument(
        "--threads", type=int, default=4, help="Number of threads"
    )
    cracker_parser.add_argument(
        "--max-passwords",
        type=int,
        default=100000,
        help="Max passwords for Markov attack",
    )
    cracker_parser.add_argument(
        "--charset",
        default="luds",
        help="Character set for brute force (l=lower, u=upper, d=digit, s=special)",
    )
    cracker_parser.add_argument(
        "--min-length", type=int, default=1, help="Min password length for brute force"
    )
    cracker_parser.add_argument(
        "--max-length", type=int, default=8, help="Max password length for brute force"
    )
    cracker_parser.add_argument("--rainbow-table", help="Rainbow table path")

    # Network Scanner
    network_parser = subparsers.add_parser("scan", help="Network scanning tools")
    network_parser.add_argument(
        "-t", "--target", required=True, help="Target IP or CIDR range"
    )
    network_parser.add_argument(
        "-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000, 80,443)"
    )
    network_parser.add_argument(
        "--threads", type=int, default=50, help="Number of threads"
    )

    # Encoder/Decoder
    encoder_parser = subparsers.add_parser("encode", help="Encoding/decoding tools")
    encoder_parser.add_argument(
        "-d", "--data", required=True, help="Data to encode/decode"
    )
    encoder_parser.add_argument(
        "-o",
        "--operation",
        required=True,
        choices=["encode", "decode"],
        help="Operation type",
    )
    encoder_parser.add_argument(
        "-e",
        "--encoding-type",
        required=True,
        choices=["base64", "url", "html", "hex"],
        help="Encoding type",
    )

    interactive_parser = subparsers.add_parser(
        "interactive", help="Start interactive menu interface"
    )

    # Password Analyzer
    analyzer_parser = subparsers.add_parser(
        "analyze", help="Password strength analysis"
    )
    analyzer_group = analyzer_parser.add_mutually_exclusive_group(required=True)
    analyzer_group.add_argument("-p", "--password", help="Single password to analyze")
    analyzer_group.add_argument("-f", "--file", help="File with passwords to analyze")

    # Rainbow Table Generator
    rainbow_parser = subparsers.add_parser(
        "generate-rainbow", help="Generate a rainbow table"
    )
    rainbow_parser.add_argument(
        "-w", "--wordlist", required=True, help="Path to the wordlist"
    )
    rainbow_parser.add_argument(
        "-o", "--output", required=True, help="Path to save the rainbow table"
    )
    rainbow_parser.add_argument(
        "-a",
        "--hash-type",
        default="md5",
        help="Hash algorithm",
        choices=["md5", "sha1", "sha256", "sha512"],
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.mode:
        parser.print_help()
        return

    try:
        if args.mode == "crack":
            password_cracker_mode(args)
        elif args.mode == "scan":
            network_scanner_mode(args)
        elif args.mode == "encode":
            encoder_mode(args)
        elif args.mode == "analyze":
            password_analyzer_mode(args)
        elif args.mode == "interactive":
            interactive_mode(args)
        elif args.mode == "generate-rainbow":
            generate_rainbow_mode(args)
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"\n[!] {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()
