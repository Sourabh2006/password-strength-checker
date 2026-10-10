"""
CLI Entrypoint for the Password Strength Checker & Auditing Tool.
Provides interactive hidden input (via getpass), single evaluation,
JSON output, and benchmark demo mode.
Strictly adheres to zero persistent storage and volatile-memory-only processing.
"""

import sys
import getpass
import argparse
import json

# Ensure UTF-8 output on Windows consoles if available
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from src.checker import PasswordStrengthChecker
from src.models import EvaluationResult, StrengthLevel

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"


def render_strength_bar(score: int, width: int = 24) -> str:
    """Renders a strength meter bar."""
    filled_len = int(round((score / 100.0) * width))
    empty_len = width - filled_len
    # Use ASCII-compatible symbols for maximum terminal compatibility
    bar = "=" * filled_len + "-" * empty_len
    return bar



def print_evaluation_report(result: EvaluationResult):
    """Prints a styled terminal report of the password evaluation."""
    color = result.strength_level.color_code
    level_name = result.strength_level.value.upper()
    bar = render_strength_bar(result.score)

    print()
    print(f"{BOLD}{'=' * 65}{RESET}")
    print(f"{BOLD}           PASSWORD STRENGTH AUDIT REPORT{RESET}")
    print(f"{BOLD}{'=' * 65}{RESET}")

    # Strength & Score Meter
    print(f"Overall Score:  {BOLD}{color}{result.score}/100 [{bar}] {level_name}{RESET}")
    print(f"Password Length: {BOLD}{result.length} characters{RESET}")
    print(f"{'-' * 65}")

    # Character Diversity
    variety = result.variety
    checks = [
        ("Lowercase (a-z)", variety.has_lowercase, variety.lowercase_count),
        ("Uppercase (A-Z)", variety.has_uppercase, variety.uppercase_count),
        ("Digits (0-9)", variety.has_digits, variety.digit_count),
        ("Special Symbols", variety.has_symbols, variety.symbol_count),
    ]
    print(f"{BOLD}Character Diversity:{RESET}")
    for label, present, count in checks:
        icon = f"{GREEN}[+]{RESET}" if present else f"{RED}[-]{RESET}"
        print(f"  {icon} {label:<20} : {count} chars")
    print(f"  Active Character Pool Size (R): {variety.pool_size}")
    print(f"  Unique Characters: {variety.unique_char_count} / {result.length}")
    print(f"{'-' * 65}")

    # Entropy Metrics
    entropy = result.entropy
    print(f"{BOLD}Entropy Metrics (Local Volatile Calculation):{RESET}")
    print(f"  Shannon Entropy per Char : {BOLD}{entropy.shannon_entropy_per_char:.3f}{RESET} bits/symbol")
    print(f"  Total Shannon Entropy    : {BOLD}{entropy.total_shannon_entropy:.2f}{RESET} bits")
    print(f"  Keyspace Combinatorial   : {BOLD}{entropy.keyspace_entropy:.2f}{RESET} bits")
    print(f"{'-' * 65}")

    # Vulnerability & Pattern Warnings
    if result.patterns:
        print(f"{BOLD}{RED}Detected Vulnerabilities & Predictable Patterns:{RESET}")
        for idx, p in enumerate(result.patterns, 1):
            sev_color = RED if p.severity in ("critical", "high") else YELLOW
            print(f"  {idx}. [{sev_color}{p.severity.upper()}{RESET}] {p.description}")
        print(f"{'-' * 65}")
    else:
        print(f"{GREEN}[+] No predictable patterns, dictionary matches, or sequences found.{RESET}")
        print(f"{'-' * 65}")

    # Actionable Improvement Suggestions
    print(f"{BOLD}{CYAN}Actionable Recommendations:{RESET}")
    for idx, sug in enumerate(result.suggestions, 1):
        print(f"  {idx}. {sug}")

    print(f"{BOLD}{'=' * 65}{RESET}")
    print(f"{DIM}Note: Passwords evaluated in volatile memory only. Never logged or stored.{RESET}")
    print()


def run_benchmark_demo():
    """Runs standard benchmark passwords showing Weak, Moderate, and Robust scoring."""
    checker = PasswordStrengthChecker()

    test_passwords = [
        # Weak
        ("123456", "Sequential numeric digits"),
        ("password", "Top dictionary word"),
        ("qwerty", "QWERTY keyboard walk"),
        ("p@ssword", "Weak leetspeak substitution"),
        ("aaaa1111", "Repeated characters & chunk"),
        ("admin123", "Common administrative prefix + sequence"),
        # Moderate
        ("Summer2023!", "Dictionary word + year + symbol"),
        ("Tr0ub4dor&", "Leetspeak stem + symbol"),
        ("BlueSky99", "Compound words + digits"),
        ("CorrectHorse1", "XKCD style 2-word + digit"),
        # Robust / Strong
        ("K9#m$P2!vL8@qR4&", "Randomized 16-char 4-class string"),
        ("correct-horse-battery-staple-99!", "High-entropy multi-word passphrase"),
        ("Xj8$wL2#vQ9!mZ4&pB7*", "Randomized 20-char high entropy"),
    ]

    print(f"\n{BOLD}{'=' * 85}{RESET}")
    print(f"{BOLD}             PASSWORD STRENGTH BENCHMARK AUDITING SUITE{RESET}")
    print(f"{BOLD}{'=' * 85}{RESET}")
    print(f"{'Password (Sample)':<35} | {'Length':<6} | {'Entropy (H)':<11} | {'Score':<5} | {'Strength Level'}")
    print(f"{'-' * 85}")

    for pwd, note in test_passwords:
        res = checker.evaluate(pwd)
        color = res.strength_level.color_code
        print(
            f"{pwd:<35} | "
            f"{res.length:<6} | "
            f"{res.entropy.total_shannon_entropy:>7.1f} bits | "
            f"{res.score:>3}/100 | "
            f"{color}{res.strength_level.value:<12}{RESET}"
        )

    print(f"{'=' * 85}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker & Auditing Tool (Credential Auditing & Entropy)"
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Password to evaluate directly (for automated testing/audits). Note: hidden input via interactive prompt is recommended for security.",
        default=None,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output evaluation results in machine-readable JSON format (password itself is never emitted).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run benchmark suite showing evaluation across Weak, Moderate, and Robust credentials.",
    )

    args = parser.parse_args()

    checker = PasswordStrengthChecker()

    if args.demo:
        run_benchmark_demo()
        return

    password = args.password
    if password is None:
        try:
            # Secure hidden prompt - input is not echoed to console
            password = getpass.getpass("Enter password to evaluate (input is hidden): ")
        except (KeyboardInterrupt, EOFError):
            print("\nEvaluation cancelled.")
            sys.exit(0)

    result = checker.evaluate(password)

    # Clean up local reference to raw password
    del password

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_evaluation_report(result)


if __name__ == "__main__":
    main()
