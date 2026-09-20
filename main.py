#!/usr/bin/env python3
"""
SEC-SUITE - Security Testing Toolkit
Author: gab-dev-7
"""

import argparse
import sys
import logging
from datetime import datetime, timezone

from attacks.dictionary import DictionaryAttack
from attacks.rainbow import RainbowAttack
from attacks.markov import MarkovAttack
from attacks.bruteforce import BruteForceAttack
from attacks.rules import RuleBasedAttack
from utils.banner import show_banner
from utils.crypto import hash_password, identify_hash_type
from utils.password_analyzer import analyze_password_strength
from utils.output import write_output


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("sec-suite.log", mode="a"),
        ],
    )


def _build_attack(args):
    """Instantiate the correct attack object from parsed args."""
    if args.attack_mode == "dictionary":
        return DictionaryAttack(
            wordlist_path=args.wordlist,
            hash_type=args.hash_type,
            max_processes=args.threads,
        )
    elif args.attack_mode == "markov":
        return MarkovAttack(
            training_file=args.wordlist,
            hash_type=args.hash_type,
            max_processes=args.threads,
            max_passwords=args.max_passwords,
        )
    elif args.attack_mode == "bruteforce":
        return BruteForceAttack(
            hash_type=args.hash_type,
            charset=args.charset,
            min_length=args.min_length,
            max_length=args.max_length,
            max_processes=args.threads,
        )
    elif args.attack_mode == "rainbow":
        return RainbowAttack(args.rainbow_table)
    elif args.attack_mode == "rules":
        return RuleBasedAttack(
            wordlist_path=args.wordlist,
            hash_type=args.hash_type,
            rule_set=args.rule_set,
            max_processes=args.threads,
        )
    else:
        print(f"Unknown attack mode: {args.attack_mode}")
        return None


def password_cracker_mode(args):
    timestamp = datetime.now(timezone.utc).isoformat()

    if not any([
        args.target_hash,
        getattr(args, "target_file", None),
        args.test_password,
        getattr(args, "count", False),
    ]):
        print("[!] Provide --target-hash, --target-file, --test-password, or --count")
        return None

    if getattr(args, "threads", 1) < 1:
        print("[!] --threads must be at least 1")
        return None

    if args.attack_mode == "rainbow" and not args.rainbow_table and not args.test_password:
        print("[!] --rainbow-table is required when using -m rainbow")
        return None

    if getattr(args, "count", False):
        if not args.attack_mode:
            print("[!] --attack-mode / -m is required for candidate counting. Choose: dictionary, markov, bruteforce, rainbow, rules")
            return None
        attack = _build_attack(args)
        if attack is None:
            return None
        count = attack.candidate_count()
        print(f"[*] Estimated candidates: {count}")
        return None

    # Multi-hash mode
    if getattr(args, "target_file", None):
        if not args.attack_mode:
            print("[!] --attack-mode / -m is required for cracking. Choose: dictionary, markov, bruteforce, rainbow, rules")
            return None
        try:
            with open(args.target_file, "r", encoding="utf-8") as f:
                hashes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Hash file not found: {args.target_file}")
            return None

        print(f"[*] Multi-hash mode: {len(hashes)} hashes loaded")
        attacks = {}
        results = []
        for h in hashes:
            ht = args.hash_type or identify_hash_type(h)
            if not ht:
                print(f"[!] Cannot detect hash type for: {h} — skipping")
                results.append({"hash": h, "hash_type": None, "password": None, "cracked": False})
                continue
            if ht not in attacks:
                original_ht = args.hash_type
                args.hash_type = ht
                try:
                    attacks[ht] = _build_attack(args)
                finally:
                    args.hash_type = original_ht
            attack = attacks[ht]
            if attack is None:
                return None
            found = attack.crack(h)
            results.append({
                "hash": h,
                "hash_type": ht,
                "password": found,
                "cracked": found is not None,
            })
            if found:
                print(f"\n[+] {h} → {found}")
            else:
                print(f"\n[-] {h} → not found")

        return {
            "_type": "crack",
            "timestamp": timestamp,
            "attack_mode": args.attack_mode,
            "results": results,
        }

    # Single-hash mode
    hash_type = args.hash_type
    if not hash_type and args.target_hash:
        hash_type = identify_hash_type(args.target_hash)
        if hash_type:
            print(f"Auto-detected hash type: {hash_type}")
        else:
            print("Could not auto-detect hash type. Please specify with -a")
            return None
        args.hash_type = hash_type

    if args.target_hash:
        attack = _build_attack(args)
        if attack is None:
            return None
        found = attack.crack(args.target_hash)
        if found:
            print(f"\n[+] Password found: {found}")
        else:
            print("\n[-] Password not found")

        return {
            "_type": "crack",
            "timestamp": timestamp,
            "attack_mode": args.attack_mode,
            "results": [
                {
                    "hash": args.target_hash,
                    "hash_type": hash_type,
                    "password": found,
                    "cracked": found is not None,
                }
            ],
        }

    elif args.test_password:
        if not hash_type:
            hash_type = "sha256"
        hash_result = hash_password(args.test_password, hash_type)
        print(f"Hash ({hash_type}): {hash_result}")
        return None

    return None


def network_scanner_mode(args):
    from tools.network_scanner import NetworkScanner

    scanner = NetworkScanner(
        target=args.target,
        ports=args.ports,
        max_threads=args.threads,
        timeout=args.timeout,
        scan_type=args.scan_type,
    )
    host_results = scanner.scan()

    # Flatten for CSV compatibility while preserving host info for multi-host scans
    all_open = []
    for hr in host_results:
        for port_entry in hr["open_ports"]:
            all_open.append({"host": hr["host"], **port_entry})

    return {
        "_type": "scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "ports": args.ports,
        "scan_type": args.scan_type,
        "hosts": host_results,       # full per-host breakdown
        "open_ports": all_open,      # flattened list with host field for CSV
    }


def encoder_mode(args):
    from tools.encoder import encode_decode

    result = encode_decode(
        data=args.data, operation=args.operation, encoding_type=args.encoding_type
    )
    print(f"Result: {result}")


def password_analyzer_mode(args):
    timestamp = datetime.now(timezone.utc).isoformat()

    if args.password:
        result = analyze_password_strength(args.password)
        print(f"\nPassword Analysis for: {args.password}")
        print("=" * 50)
        for item in result["feedback"]:
            print(item)
        if result["recommendations"]:
            print("\nRecommendations:")
            for item in result["recommendations"]:
                print(f"- {item}")
        print(f"\nFinal Strength Score: {result['score']}/100")
        print(f"Strength: {result['strength']}")
        return {
            "_type": "analyze",
            "timestamp": timestamp,
            "results": [{"password": args.password, **result}],
        }

    elif args.file:
        try:
            all_results = []
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if password:
                        result = analyze_password_strength(password)
                        print(f"Line {line_num}: {password} - Strength: {result['score']}/100")
                        all_results.append({"password": password, **result})
            return {"_type": "analyze", "timestamp": timestamp, "results": all_results}
        except FileNotFoundError:
            print(f"File not found: {args.file}")

    return None


def generate_rainbow_mode(args):
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
    from interactive_cli import main as interactive_main
    interactive_main()


def _maybe_save(result, args):
    """Write result to disk if --output was supplied."""
    if result is None or not args.output:
        return
    write_output(result, args.output, args.format or "json")


def main():
    show_banner()

    parser = argparse.ArgumentParser(description="SEC-SUITE Security Toolkit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # ── crack ──
    cracker_parser = subparsers.add_parser("crack", help="Password cracking tools")
    hash_source = cracker_parser.add_mutually_exclusive_group()
    hash_source.add_argument("-t", "--target-hash", help="Target hash to crack")
    hash_source.add_argument("--target-file", help="File with one hash per line (multi-hash mode)")
    cracker_parser.add_argument("-p", "--test-password", help="Test password hashing")
    cracker_parser.add_argument(
        "-a", "--hash-type",
        choices=["md5", "sha1", "sha256", "sha512", "bcrypt", "scrypt", "argon2"],
        help="Hash algorithm",
    )
    cracker_parser.add_argument(
        "-m", "--attack-mode",
        choices=["dictionary", "markov", "bruteforce", "rainbow", "rules"],
        help="Attack method (required for cracking; not needed with --test-password)",
    )
    cracker_parser.add_argument("-w", "--wordlist", default="data/rockyou.txt", help="Wordlist path")
    cracker_parser.add_argument("--threads", type=int, default=4, help="Number of processes")
    cracker_parser.add_argument("--max-passwords", type=int, default=100000, help="Max passwords for Markov attack")
    cracker_parser.add_argument("--charset", default="luds", help="Character set for brute force (l=lower, u=upper, d=digit, s=special)")
    cracker_parser.add_argument("--min-length", type=int, default=1, help="Min password length for brute force")
    cracker_parser.add_argument("--max-length", type=int, default=8, help="Max password length for brute force")
    cracker_parser.add_argument("--rainbow-table", help="Rainbow table path")
    cracker_parser.add_argument("--count", action="store_true", help="Print estimated candidate count and exit without cracking")
    cracker_parser.add_argument(
        "--rule-set", default="all",
        choices=["basic", "numbers", "leet", "special", "all"],
        help="Rule set for rules attack (default: all)",
    )
    cracker_parser.add_argument("--output", help="Save results to file")
    cracker_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (default: json)")

    # ── scan ──
    network_parser = subparsers.add_parser("scan", help="Network scanning tools")
    network_parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")
    network_parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000, 80,443)")
    network_parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    network_parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    network_parser.add_argument(
        "--scan-type", choices=["syn", "connect"], default="syn",
        help="Scan strategy: syn (stealth, needs root) or connect (no root, grabs banners)",
    )
    network_parser.add_argument("--output", help="Save results to file")
    network_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (default: json)")

    # ── encode ──
    encoder_parser = subparsers.add_parser("encode", help="Encoding/decoding tools")
    encoder_parser.add_argument("-d", "--data", required=True, help="Data to encode/decode")
    encoder_parser.add_argument("-o", "--operation", required=True, choices=["encode", "decode"])
    encoder_parser.add_argument("-e", "--encoding-type", required=True, choices=["base64", "url", "html", "hex"])

    # ── interactive ──
    subparsers.add_parser("interactive", help="Start interactive menu interface")

    # ── analyze ──
    analyzer_parser = subparsers.add_parser("analyze", help="Password strength analysis")
    analyzer_group = analyzer_parser.add_mutually_exclusive_group(required=True)
    analyzer_group.add_argument("-p", "--password", help="Single password to analyze")
    analyzer_group.add_argument("-f", "--file", help="File with passwords to analyze")
    analyzer_parser.add_argument("--output", help="Save results to file")
    analyzer_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (default: json)")

    # ── generate-rainbow ──
    rainbow_parser = subparsers.add_parser("generate-rainbow", help="Generate a rainbow table")
    rainbow_parser.add_argument("-w", "--wordlist", required=True)
    rainbow_parser.add_argument("-o", "--output", required=True)
    rainbow_parser.add_argument("-a", "--hash-type", default="md5", choices=["md5", "sha1", "sha256", "sha512"])

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.mode:
        parser.print_help()
        return

    try:
        if args.mode == "crack":
            result = password_cracker_mode(args)
            _maybe_save(result, args)
        elif args.mode == "scan":
            result = network_scanner_mode(args)
            _maybe_save(result, args)
        elif args.mode == "encode":
            encoder_mode(args)
        elif args.mode == "analyze":
            result = password_analyzer_mode(args)
            _maybe_save(result, args)
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
