#!/usr/bin/env python3
"""
SEC-SUITE Interactive CLI
A user-friendly menu-driven interface for the security toolkit
"""

import os
import sys
from typing import List, Dict, Any

# Add the current directory to path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.banner import show_banner
from utils.crypto import hash_password, identify_hash_type
from utils.password_analyzer import analyze_password_strength
from attacks.dictionary import DictionaryAttack
from attacks.markov import MarkovAttack, AdvancedPasswordGenerator
from attacks.bruteforce import BruteForceAttack
from attacks.rainbow import RainbowAttack
from tools.network_scanner import NetworkScanner


class InteractiveCLI:
    """Interactive menu-driven interface for SEC-SUITE"""

    def __init__(self):
        self.current_menu = "main"
        self.menu_history = []
        self.screen_width = 80

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system("cls" if os.name == "nt" else "clear")

    def print_header(self, title: str):
        """Print a formatted header"""
        print("╔" + "═" * (self.screen_width - 2) + "╗")
        print("║" + title.center(self.screen_width - 2) + "║")
        print("╚" + "═" * (self.screen_width - 2) + "╝")
        print()

    def print_menu(self, title: str, options: List[Dict[str, Any]]):
        """Print a formatted menu"""
        self.print_header(title)

        for i, option in enumerate(options, 1):
            print(f"  {i}. {option['text']}")

        print(f"\n  0. {'Back' if self.menu_history else 'Exit'}")
        print("\n" + "─" * self.screen_width)

    def get_user_choice(self, max_option: int) -> int:
        """Get and validate user choice"""
        while True:
            try:
                choice = input(f"\nEnter your choice (0-{max_option}): ").strip()
                if not choice:
                    continue

                choice_num = int(choice)
                if 0 <= choice_num <= max_option:
                    return choice_num
                else:
                    print(f"Please enter a number between 0 and {max_option}")
            except ValueError:
                print("Please enter a valid number")
            except KeyboardInterrupt:
                print("\n\nOperation cancelled by user.")
                return 0

    def wait_for_enter(self, message: str = "Press Enter to continue..."):
        """Wait for user to press Enter"""
        input(f"\n{message}")

    def main_menu(self):
        """Main menu"""
        options = [
            {"text": "Password Cracking Tools", "action": self.cracking_menu},
            {"text": "Password Analysis & Hashing", "action": self.analysis_menu},
            {"text": "Security Tools", "action": self.security_tools_menu},
            {"text": "Encoding/Decoding Tools", "action": self.encoding_menu},
            {"text": "About & Help", "action": self.about_menu},
        ]

        while True:
            self.clear_screen()
            show_banner()
            self.print_menu("SEC-SUITE Main Menu", options)

            choice = self.get_user_choice(len(options))

            if choice == 0:
                print("\nThank you for using SEC-SUITE! Goodbye!")
                break
            else:
                self.menu_history.append(self.main_menu)
                options[choice - 1]["action"]()

    def cracking_menu(self):
        """Password cracking menu"""
        options = [
            {"text": "Dictionary Attack", "action": self.dictionary_attack},
            {"text": "Markov Chain Attack", "action": self.markov_attack},
            {"text": "Brute Force Attack", "action": self.brute_force_attack},
            {"text": "Rainbow Table Attack", "action": self.rainbow_attack},
            {"text": "Rule-Based Attack", "action": self.rule_based_attack},
            {"text": "Generate Rainbow Table", "action": self.generate_rainbow_table_interactive},
        ]

        while True:
            self.clear_screen()
            self.print_menu("Password Cracking Tools", options)

            choice = self.get_user_choice(len(options))

            if choice == 0:
                self.menu_history.pop()
                break
            else:
                options[choice - 1]["action"]()

    def analysis_menu(self):
        """Password analysis and hashing menu"""
        options = [
            {"text": "Password Strength Analysis", "action": self.password_analysis},
            {"text": "Password Hashing", "action": self.password_hashing},
            {"text": "Hash Type Identification", "action": self.hash_identification},
        ]

        while True:
            self.clear_screen()
            self.print_menu("Password Analysis & Hashing", options)

            choice = self.get_user_choice(len(options))

            if choice == 0:
                self.menu_history.pop()
                break
            else:
                options[choice - 1]["action"]()

    def security_tools_menu(self):
        """Security tools menu"""
        options = [
            {"text": "Network Port Scanner", "action": self.network_scanner},
            {"text": "Generate Password List", "action": self.generate_passwords},
        ]

        while True:
            self.clear_screen()
            self.print_menu("Security Tools", options)

            choice = self.get_user_choice(len(options))

            if choice == 0:
                self.menu_history.pop()
                break
            else:
                options[choice - 1]["action"]()

    def encoding_menu(self):
        """Encoding/decoding menu"""
        options = [
            {
                "text": "Base64 Encoding/Decoding",
                "action": lambda: self.encoding_tool("base64"),
            },
            {
                "text": "URL Encoding/Decoding",
                "action": lambda: self.encoding_tool("url"),
            },
            {
                "text": "HTML Encoding/Decoding",
                "action": lambda: self.encoding_tool("html"),
            },
            {
                "text": "Hex Encoding/Decoding",
                "action": lambda: self.encoding_tool("hex"),
            },
        ]

        while True:
            self.clear_screen()
            self.print_menu("Encoding/Decoding Tools", options)

            choice = self.get_user_choice(len(options))

            if choice == 0:
                self.menu_history.pop()
                break
            else:
                options[choice - 1]["action"]()

    def about_menu(self):
        """About and help menu"""
        self.clear_screen()
        self.print_header("About SEC-SUITE")

        about_text = [
            "SEC-SUITE v2.0 - Advanced Security Testing Toolkit",
            "",
            "Features:",
            "  • Multiple password cracking methods",
            "  • Modern hash algorithm support",
            "  • Multi-threaded attacks",
            "  • Network security tools",
            "  • Encoding/decoding utilities",
            "",
            "Legal Notice:",
            "  This tool is for educational and authorized",
            "  security testing only. Use responsibly!",
            "",
            "GitHub: https://github.com/gab-dev-7/sec-suite",
        ]

        for line in about_text:
            print(f"  {line}")

        self.wait_for_enter()
        self.menu_history.pop()

    def dictionary_attack(self):
        """Interactive dictionary attack"""
        self.clear_screen()
        self.print_header("Dictionary Attack")

        target_hash = input("Enter target hash: ").strip()
        if not target_hash:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        # Auto-detect hash type
        hash_type = identify_hash_type(target_hash)
        if hash_type:
            print(f"Auto-detected hash type: {hash_type}")
            use_auto = input("Use auto-detected type? (y/n): ").lower().strip()
            if use_auto != "y":
                hash_type = None

        if not hash_type:
            hash_type = input(
                "Enter hash type (md5, sha1, sha256, sha512, bcrypt): "
            ).strip()

        wordlist = (
            input("Enter wordlist path [data/rockyou.txt]: ").strip()
            or "data/rockyou.txt"
        )
        threads = input("Enter number of threads [4]: ").strip() or "4"

        print(f"\nStarting dictionary attack...")
        print(f"Target: {target_hash}")
        print(f"Type: {hash_type}")
        print(f"Wordlist: {wordlist}")
        print(f"Threads: {threads}")
        print("-" * 50)

        try:
            attack = DictionaryAttack(wordlist, hash_type, max_processes=int(threads))
            result = attack.crack(target_hash)

            if result:
                print(f"\n[+] Password found: {result}")
            else:
                print(f"\n[-] Password not found in wordlist")

        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def markov_attack(self):
        """Interactive Markov chain attack"""
        self.clear_screen()
        self.print_header("Markov Chain Attack")

        target_hash = input("Enter target hash: ").strip()
        if not target_hash:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        hash_type = input("Enter hash type (md5, sha1, sha256, sha512): ").strip()
        training_file = (
            input("Enter training file [data/rockyou.txt]: ").strip()
            or "data/rockyou.txt"
        )
        max_passwords = (
            input("Enter max passwords to generate [50000]: ").strip() or "50000"
        )
        threads = input("Enter number of threads [4]: ").strip() or "4"

        print(f"\nStarting Markov chain attack...")
        print("This may take a while as we generate password candidates...")

        try:
            attack = MarkovAttack(
                training_file, hash_type, int(threads), int(max_passwords)
            )
            result = attack.crack(target_hash)

            if result:
                print(f"\n[+] Password found: {result}")
            else:
                print(f"\n[-] Password not found with Markov attack")

        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def brute_force_attack(self):
        """Interactive brute force attack"""
        self.clear_screen()
        self.print_header("Brute Force Attack")

        target_hash = input("Enter target hash: ").strip()
        if not target_hash:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        hash_type = input("Enter hash type (md5, sha1, sha256, sha512): ").strip()

        print("\nCharacter sets:")
        print("  l - lowercase letters (abc...)")
        print("  u - uppercase letters (ABC...)")
        print("  d - digits (012...)")
        print("  s - special characters (!@#...)")
        charset = input("Enter character sets [lud]: ").strip() or "lud"

        min_len = input("Enter minimum length [1]: ").strip() or "1"
        max_len = input("Enter maximum length [6]: ").strip() or "6"
        threads = input("Enter number of threads [4]: ").strip() or "4"

        print(f"\nStarting brute force attack...")
        print(
            f"This will test up to {BruteForceAttack(hash_type, charset, int(min_len), int(max_len), max_processes=1).calculate_total_combinations()} combinations"
        )
        print("This may take a very long time!")

        proceed = input("Proceed? (y/n): ").lower().strip()
        if proceed != "y":
            print("Attack cancelled.")
            self.wait_for_enter()
            return

        try:
            attack = BruteForceAttack(
                hash_type, charset, int(min_len), int(max_len), max_processes=int(threads)
            )
            result = attack.crack(target_hash)

            if result:
                print(f"\n[+] Password found: {result}")
            else:
                print(f"\n[-] Password not found with brute force")

        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def rainbow_attack(self):
        """Interactive rainbow table attack"""
        self.clear_screen()
        self.print_header("Rainbow Table Attack")

        target_hash = input("Enter target hash: ").strip()
        if not target_hash:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        rainbow_table = input("Enter rainbow table file path: ").strip()
        if not rainbow_table:
            print("Rainbow table path required!")
            self.wait_for_enter()
            return

        print(f"\nStarting rainbow table attack...")

        try:
            attack = RainbowAttack(rainbow_table)
            result = attack.crack(target_hash)

            if result:
                print(f"\n[+] Password found: {result}")
            else:
                print(f"\n[-] Hash not found in rainbow table")

        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def rule_based_attack(self):
        """Interactive rule-based attack"""
        self.clear_screen()
        self.print_header("Rule-Based Attack")

        target_hash = input("Enter target hash: ").strip()
        if not target_hash:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        hash_type = identify_hash_type(target_hash)
        if hash_type:
            print(f"Auto-detected hash type: {hash_type}")
            use_auto = input("Use auto-detected type? (y/n): ").lower().strip()
            if use_auto != "y":
                hash_type = None
        if not hash_type:
            hash_type = input("Enter hash type (md5, sha1, sha256, sha512, bcrypt): ").strip()

        wordlist = input("Enter wordlist path [data/rockyou.txt]: ").strip() or "data/rockyou.txt"

        print("\nAvailable rule sets:")
        print("  basic   — case transforms + reverse")
        print("  numbers — append/prepend digits, append year")
        print("  leet    — leet-speak substitutions")
        print("  special — append special characters")
        print("  all     — all of the above (default)")
        rule_set = input("Enter rule set [all]: ").strip() or "all"
        if rule_set not in ("basic", "numbers", "leet", "special", "all"):
            print(f"Invalid rule set '{rule_set}', using 'all'.")
            rule_set = "all"

        threads = input("Enter number of threads [4]: ").strip() or "4"

        print(f"\nStarting rule-based attack...")
        try:
            from attacks.rules import RuleBasedAttack
            attack = RuleBasedAttack(wordlist, hash_type, rule_set=rule_set, max_processes=int(threads))
            result = attack.crack(target_hash)
            if result:
                print(f"\n[+] Password found: {result}")
            else:
                print(f"\n[-] Password not found with rule-based attack")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def generate_rainbow_table_interactive(self):
        """Interactive rainbow table generation"""
        self.clear_screen()
        self.print_header("Generate Rainbow Table")

        wordlist = input("Enter wordlist path: ").strip()
        if not wordlist:
            print("Wordlist path cannot be empty!")
            self.wait_for_enter()
            return

        output_path = input("Enter output path for rainbow table [rainbow.json]: ").strip() or "rainbow.json"
        hash_type = input("Enter hash type (md5, sha1, sha256, sha512) [md5]: ").strip() or "md5"

        valid_hash_types = ["md5", "sha1", "sha256", "sha512"]
        if hash_type not in valid_hash_types:
            print(f"Invalid hash type! Choose from: {', '.join(valid_hash_types)}")
            self.wait_for_enter()
            return

        print(f"\nStarting rainbow table generation...")
        print(f"Wordlist: {wordlist}")
        print(f"Output: {output_path}")
        print(f"Type: {hash_type}")
        print("-" * 50)

        try:
            attack = RainbowAttack()
            attack.generate_rainbow_table(wordlist, output_path, hash_type)
            if os.path.exists(output_path):
                print(f"\n[+] Rainbow table generated at {output_path}")
            else:
                print(f"\n[!] Failed to generate rainbow table. Check the error above.")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def password_analysis(self):
        """Interactive password strength analysis"""
        self.clear_screen()
        self.print_header("Password Strength Analysis")

        password = input("Enter password to analyze: ").strip()
        if not password:
            print("Password cannot be empty!")
            self.wait_for_enter()
            return

        print(f"\nAnalyzing password: {password}")
        print("-" * 50)

        try:
            result = analyze_password_strength(password)
            print(f"\nStrength: {result['strength']} ({result['score']}/100)")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def password_hashing(self):
        """Interactive password hashing"""
        self.clear_screen()
        self.print_header("Password Hashing")

        password = input("Enter password to hash: ").strip()
        if not password:
            print("Password cannot be empty!")
            self.wait_for_enter()
            return

        algorithm = (
            input(
                "Enter algorithm (md5, sha1, sha256, sha512, bcrypt) [sha256]: "
            ).strip()
            or "sha256"
        )

        print(f"\nHashing password with {algorithm}...")

        try:
            hashed = hash_password(password, algorithm)
            print(f"Hash ({algorithm.upper()}): {hashed}")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def hash_identification(self):
        """Interactive hash type identification"""
        self.clear_screen()
        self.print_header("Hash Type Identification")

        hash_input = input("Enter hash to identify: ").strip()
        if not hash_input:
            print("Hash cannot be empty!")
            self.wait_for_enter()
            return

        print(f"\nAnalyzing hash: {hash_input}")
        print("-" * 50)

        try:
            hash_type = identify_hash_type(hash_input)
            if hash_type:
                print(f"[*] Identified hash type: {hash_type}")
            else:
                print("[-] Could not identify hash type")
                print("This might be an unsupported or custom hash format")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def network_scanner(self):
        """Interactive network scanner"""
        self.clear_screen()
        self.print_header("Network Port Scanner")

        target = input("Enter target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24): ").strip()
        if not target:
            print("Target cannot be empty!")
            self.wait_for_enter()
            return

        ports = input("Enter port range [1-1000]: ").strip() or "1-1000"
        threads = input("Enter number of threads [50]: ").strip() or "50"
        timeout = input("Enter timeout in seconds [1.0]: ").strip() or "1.0"

        print("\nScan types:")
        print("  syn     — stealth SYN scan (requires root/sudo)")
        print("  connect — TCP connect scan (no root needed, grabs banners)")
        scan_type = input("Enter scan type [connect]: ").strip() or "connect"
        if scan_type not in ("syn", "connect"):
            print("Invalid scan type. Using 'connect'.")
            scan_type = "connect"

        print(f"\nStarting {scan_type} scan on {target}...")
        try:
            scanner = NetworkScanner(target, ports, int(threads), float(timeout), scan_type=scan_type)
            scanner.scan()
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def generate_passwords(self):
        """Interactive password generation"""
        self.clear_screen()
        self.print_header("Password List Generation")

        training_file = (
            input("Enter training file [data/rockyou.txt]: ").strip()
            or "data/rockyou.txt"
        )
        
        if not os.path.exists(training_file):
            print(f"Error: Training file {training_file} not found.")
            self.wait_for_enter()
            return

        count = input("Enter number of passwords to generate [10]: ").strip() or "10"
        min_len = input("Enter minimum length [8]: ").strip() or "8"
        max_len = input("Enter maximum length [12]: ").strip() or "12"

        print(f"\nTraining model and generating passwords...")
        print("This may take a moment depending on the training file size.")

        try:
            generator = AdvancedPasswordGenerator(training_file)
            passwords = generator.generate_passwords(int(count), int(min_len), int(max_len))

            print(f"\nGenerated {len(passwords)} passwords:")
            print("-" * 50)
            for i, pwd in enumerate(passwords, 1):
                # Using strength analyzer for each generated password
                result = analyze_password_strength(pwd)
                print(f"{i:2d}. {pwd} (Score: {result['score']}/100)")
                print("-" * 20)
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()

    def encoding_tool(self, encoding_type: str):
        """Interactive encoding/decoding tool"""
        self.clear_screen()
        self.print_header(f"{encoding_type.upper()} Encoding/Decoding")

        operation = input("Choose operation (1=encode, 2=decode): ").strip()
        if operation not in ["1", "2"]:
            print("Invalid operation!")
            self.wait_for_enter()
            return

        data = input("Enter data: ").strip()
        if not data:
            print("Data cannot be empty!")
            self.wait_for_enter()
            return

        from tools.encoder import encode_decode

        try:
            op_type = "encode" if operation == "1" else "decode"
            result = encode_decode(data, op_type, encoding_type)
            print(f"\nResult: {result}")
        except Exception as e:
            print(f"\n[!] {e}")

        self.wait_for_enter()


def main():
    """Main entry point for interactive CLI"""
    try:
        cli = InteractiveCLI()
        cli.main_menu()
    except KeyboardInterrupt:
        print("\n\nThank you for using SEC-SUITE! Goodbye!")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        print("Please report this issue on GitHub.")


if __name__ == "__main__":
    main()
