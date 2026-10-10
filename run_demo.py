"""
Quick demonstration runner showing programmatic usage of the PasswordStrengthChecker.
"""

from src.checker import PasswordStrengthChecker


def main():
    checker = PasswordStrengthChecker()

    sample_passwords = [
        "p@ssword",
        "qwerty123456",
        "Summer2023!",
        "correct-horse-battery-staple-99!",
    ]

    print("=" * 70)
    print(" PROGRAMMATIC PASSWORD STRENGTH AUDIT DEMO")
    print("=" * 70)

    for pwd in sample_passwords:
        res = checker.evaluate(pwd)
        print(f"\nPassword: {pwd}")
        print(f"  Length: {res.length}")
        print(f"  Score: {res.score}/100 ({res.strength_level.value})")
        print(f"  Shannon Entropy: {res.entropy.total_shannon_entropy:.2f} bits (H={res.entropy.shannon_entropy_per_char:.2f} bits/char)")
        print(f"  Keyspace Entropy: {res.entropy.keyspace_entropy:.2f} bits")
        print(f"  Warnings: {res.warnings}")
        print(f"  Top Suggestion: {res.suggestions[0] if res.suggestions else 'None'}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
