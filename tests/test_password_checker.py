"""
Comprehensive Unit Test Suite for Password Strength Checker.
Covers:
- Weak passwords (dictionary, sequential, keyboard walks, leetspeak, repeats)
- Moderate passwords (hybrid patterns, partial complexity)
- Robust/Strong passwords (high entropy, randomized, passphrases)
- Shannon entropy and mathematical computations
- Leetspeak and pattern detection accuracy
- Actionable improvement suggestions
- Zero persistent storage and privacy guarantees
- Edge cases (empty string, single character, whitespace, unicode)
"""

import math
import os
import unittest
from src.checker import PasswordStrengthChecker
from src.models import StrengthLevel
from src.entropy import calculate_entropy, analyze_character_variety
from src.patterns import (
    normalize_leetspeak,
    detect_dictionary_and_leetspeak,
    detect_sequential_patterns,
    detect_keyboard_walks,
    detect_repeated_patterns,
)


class TestEntropyCalculations(unittest.TestCase):
    """Verifies mathematical correctness of Shannon and keyspace entropy."""

    def test_shannon_entropy_zero_for_identical_characters(self):
        # A string of identical characters has probability 1.0 for that character -> H = 0.0 bits
        res = calculate_entropy("aaaaaaa")
        self.assertAlmostEqual(res.shannon_entropy_per_char, 0.0, places=5)
        self.assertAlmostEqual(res.total_shannon_entropy, 0.0, places=5)

    def test_shannon_entropy_uniform_distribution(self):
        # 2 equally likely characters: p = 0.5 each -> H = -2 * (0.5 * log2(0.5)) = 1.0 bit/char
        res = calculate_entropy("abababab")
        self.assertAlmostEqual(res.shannon_entropy_per_char, 1.0, places=5)
        self.assertAlmostEqual(res.total_shannon_entropy, 8.0, places=5)

        # 4 equally likely characters: p = 0.25 each -> H = 2.0 bits/char
        res4 = calculate_entropy("abcd")
        self.assertAlmostEqual(res4.shannon_entropy_per_char, 2.0, places=5)
        self.assertAlmostEqual(res4.total_shannon_entropy, 8.0, places=5)

    def test_keyspace_entropy_formula(self):
        # 8 lowercase letters: pool = 26, keyspace = 8 * log2(26)
        res = calculate_entropy("abcdefgh")
        expected_keyspace = 8 * math.log2(26)
        self.assertAlmostEqual(res.keyspace_entropy, expected_keyspace, places=4)
        self.assertEqual(res.pool_size, 26)

    def test_variety_and_pool_size(self):
        # Mix of lower, upper, digit, symbol
        variety = analyze_character_variety("Ab1!")
        self.assertTrue(variety.has_lowercase)
        self.assertTrue(variety.has_uppercase)
        self.assertTrue(variety.has_digits)
        self.assertTrue(variety.has_symbols)
        self.assertEqual(variety.variety_count, 4)
        self.assertEqual(variety.pool_size, 26 + 26 + 10 + 33)


class TestPatternDetection(unittest.TestCase):
    """Verifies accurate detection of weaknesses and leetspeak substitutions."""

    def test_leetspeak_normalization(self):
        self.assertEqual(normalize_leetspeak("p@ssword"), "password")
        self.assertEqual(normalize_leetspeak("P@55w0rd"), "password")
        self.assertEqual(normalize_leetspeak("4dm1n"), "admin")
        self.assertEqual(normalize_leetspeak("w3lc0m3"), "welcome")

    def test_detect_leetspeak_substitution(self):
        # Acceptance Criterion: Accurately flags predictable patterns and weak substitutions ('p@ssword')
        matches = detect_dictionary_and_leetspeak("p@ssword")
        self.assertTrue(any(m.pattern_type in ("leetspeak", "leetspeak_substring") for m in matches))

        matches_leet2 = detect_dictionary_and_leetspeak("P@55w0rd")
        self.assertTrue(any(m.pattern_type in ("leetspeak", "leetspeak_substring") for m in matches_leet2))

    def test_detect_exact_dictionary(self):
        matches = detect_dictionary_and_leetspeak("password")
        self.assertTrue(any(m.pattern_type == "dictionary" for m in matches))

        matches_admin = detect_dictionary_and_leetspeak("admin")
        self.assertTrue(any(m.pattern_type == "dictionary" for m in matches_admin))

    def test_detect_sequential_patterns(self):
        # Numeric sequences
        matches = detect_sequential_patterns("123456")
        self.assertTrue(any(m.pattern_type == "sequence" and "123456" in m.matched_text for m in matches))

        # Reverse numeric
        matches_rev = detect_sequential_patterns("654321")
        self.assertTrue(any(m.pattern_type == "sequence" for m in matches_rev))

        # Alphabetic sequence
        matches_alpha = detect_sequential_patterns("abcdef")
        self.assertTrue(any(m.pattern_type == "sequence" for m in matches_alpha))

    def test_detect_keyboard_walks(self):
        # Horizontal QWERTY walk
        matches = detect_keyboard_walks("qwerty")
        self.assertTrue(any(m.pattern_type == "keyboard_walk" for m in matches))

        # Reverse walk
        matches_rev = detect_keyboard_walks("poiuytrew")
        self.assertTrue(any(m.pattern_type == "keyboard_walk" for m in matches_rev))

        # Diagonal walk
        matches_diag = detect_keyboard_walks("1qaz")
        self.assertTrue(any(m.pattern_type in ("keyboard_diagonal", "keyboard_walk") for m in matches_diag))

    def test_detect_repeated_patterns(self):
        # Single char repeats
        matches = detect_repeated_patterns("aaaa")
        self.assertTrue(any(m.pattern_type == "repeated_characters" for m in matches))

        # Chunk repeats
        matches_chunk = detect_repeated_patterns("abcabcabc")
        self.assertTrue(any(m.pattern_type == "repeated_chunk" for m in matches_chunk))


class TestPasswordScoring(unittest.TestCase):
    """Demonstrates scoring against weak, moderate, and robust credentials."""

    def setUp(self):
        self.checker = PasswordStrengthChecker()

    def test_weak_passwords(self):
        weak_samples = [
            "123456",
            "password",
            "qwerty",
            "p@ssword",
            "P@55w0rd",
            "aaaa1111",
            "admin123",
            "letmein",
            "short",
        ]
        for pwd in weak_samples:
            res = self.checker.evaluate(pwd)
            self.assertIn(
                res.strength_level,
                (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK),
                f"Password '{pwd}' should be scored as Very Weak or Weak, but got {res.strength_level} (Score: {res.score})"
            )
            self.assertLessEqual(res.score, 45, f"Password '{pwd}' score {res.score} exceeds weak threshold")
            self.assertTrue(len(res.warnings) > 0, f"Password '{pwd}' should produce warnings")
            self.assertTrue(len(res.suggestions) > 0, f"Password '{pwd}' should produce suggestions")

    def test_moderate_passwords(self):
        moderate_samples = [
            "Summer2023!",       # Dictionary word + year + symbol
            "BlueSky99",         # 9 chars, 3 classes, compound word
            "SunnyDay88!",       # 11 chars, 4 classes, common word root
        ]
        for pwd in moderate_samples:
            res = self.checker.evaluate(pwd)
            self.assertIn(
                res.strength_level,
                (StrengthLevel.WEAK, StrengthLevel.MODERATE, StrengthLevel.STRONG),
                f"Password '{pwd}' got unexpected level: {res.strength_level}"
            )
            self.assertTrue(25 <= res.score <= 75, f"Score {res.score} not in moderate range for {pwd}")

    def test_robust_passwords(self):
        robust_samples = [
            "K9#m$P2!vL8@qR4&",                 # 16-char random 4 classes
            "correct-horse-battery-staple-99!", # 32-char passphrase with symbol
            "Xj8$wL2#vQ9!mZ4&pB7*",             # 20-char complex string
            "T7!pL9#mQ2$vW8*xR4&",              # 19-char high entropy
        ]
        for pwd in robust_samples:
            res = self.checker.evaluate(pwd)
            self.assertIn(
                res.strength_level,
                (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG),
                f"Password '{pwd}' should be Strong or Very Strong, got {res.strength_level} (Score: {res.score})"
            )
            self.assertGreaterEqual(res.score, 80, f"Password '{pwd}' score {res.score} should be >= 80")
            self.assertGreater(res.entropy.total_shannon_entropy, 50.0)


class TestActionableFeedback(unittest.TestCase):
    """Verifies that constructive suggestions and actionable feedback are provided."""

    def setUp(self):
        self.checker = PasswordStrengthChecker()

    def test_short_password_suggestions(self):
        res = self.checker.evaluate("abc")
        self.assertTrue(any("length" in s.lower() or "extend" in s.lower() for s in res.suggestions))

    def test_missing_character_types_suggestions(self):
        res = self.checker.evaluate("alllowercaseletters")
        joined_suggestions = " ".join(res.suggestions).lower()
        self.assertTrue("uppercase" in joined_suggestions)
        self.assertTrue("numbers" in joined_suggestions)
        self.assertTrue("symbols" in joined_suggestions)

    def test_leetspeak_suggestion(self):
        res = self.checker.evaluate("p@ssword")
        joined_suggestions = " ".join(res.suggestions).lower()
        self.assertTrue("leetspeak" in joined_suggestions or "substitutions" in joined_suggestions)


class TestPrivacyAndSecurityGuarantees(unittest.TestCase):
    """Verifies zero persistent storage or leakage."""

    def setUp(self):
        self.checker = PasswordStrengthChecker()

    def test_no_password_in_serialization(self):
        secret = "SuperSecretPassword123!"
        res = self.checker.evaluate(secret)
        data = res.to_dict()

        # The dictionary representation must never contain the raw password as a key or top-level field
        self.assertNotIn("password", data)
        self.assertNotIn(secret, str(data))

    def test_zero_disk_leakage(self):
        # Verify no files are written to workspace during evaluation
        files_before = set(os.listdir("."))
        self.checker.evaluate("ConfidentialPassword123!#")
        files_after = set(os.listdir("."))
        self.assertEqual(files_before, files_after)


class TestEdgeCases(unittest.TestCase):
    """Tests empty passwords, single character, whitespace, and special characters."""

    def setUp(self):
        self.checker = PasswordStrengthChecker()

    def test_empty_password(self):
        res = self.checker.evaluate("")
        self.assertEqual(res.length, 0)
        self.assertEqual(res.score, 0)
        self.assertEqual(res.strength_level, StrengthLevel.VERY_WEAK)
        self.assertEqual(res.entropy.total_shannon_entropy, 0.0)
        self.assertTrue(len(res.warnings) > 0)
        self.assertTrue(len(res.suggestions) > 0)

    def test_single_character(self):
        res = self.checker.evaluate("A")
        self.assertEqual(res.length, 1)
        self.assertEqual(res.strength_level, StrengthLevel.VERY_WEAK)
        self.assertEqual(res.entropy.shannon_entropy_per_char, 0.0)

    def test_all_spaces(self):
        res = self.checker.evaluate("    ")
        self.assertEqual(res.strength_level, StrengthLevel.VERY_WEAK)
        self.assertEqual(res.entropy.shannon_entropy_per_char, 0.0)

    def test_unicode_passwords(self):
        res = self.checker.evaluate("Pässwörd!12345#")
        self.assertGreater(res.length, 0)
        self.assertGreater(res.entropy.pool_size, 0)


class TestPasswordGenerator(unittest.TestCase):
    """Tests CSPRNG password and passphrase generation."""

    def test_random_password_generation(self):
        from src.generator import generate_random_password, estimate_crack_time
        pwd = generate_random_password(length=20, use_lower=True, use_upper=True, use_digits=True, use_symbols=True)
        self.assertEqual(len(pwd), 20)
        # Should evaluate to strong or robust
        checker = PasswordStrengthChecker()
        res = checker.evaluate(pwd)
        self.assertIn(res.strength_level, [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG])
        self.assertGreater(res.entropy.total_shannon_entropy, 50.0)

        crack_time = estimate_crack_time(res.entropy.total_shannon_entropy)
        self.assertIsInstance(crack_time, str)
        self.assertTrue(len(crack_time) > 0)

    def test_passphrase_generation(self):
        from src.generator import generate_passphrase
        phrase = generate_passphrase(word_count=5, separator="-", capitalize=True, include_number=True)
        parts = phrase.split("-")
        self.assertGreaterEqual(len(parts), 5)
        checker = PasswordStrengthChecker()
        res = checker.evaluate(phrase)
        self.assertGreaterEqual(res.score, 60)


if __name__ == "__main__":
    unittest.main()

