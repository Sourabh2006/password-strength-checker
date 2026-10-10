"""
Core Password Strength Checker and Auditor.
Orchestrates entropy calculation, character variety auditing,
pattern & vulnerability scanning, scoring, and actionable feedback generation.
"""

from typing import List
from src.models import (
    EvaluationResult,
    StrengthLevel,
    PatternMatch,
)
from src.entropy import analyze_character_variety, calculate_entropy
from src.patterns import analyze_all_patterns


class PasswordStrengthChecker:
    """
    Evaluates password strength purely in volatile memory.
    Guarantees zero persistent storage or transmission.
    """

    def __init__(self):
        pass

    def evaluate(self, password: str) -> EvaluationResult:
        """
        Performs a full security audit of the provided password.
        The password remains solely in local stack variables during execution.
        """
        length = len(password)

        # Handle empty password
        if length == 0:
            variety = analyze_character_variety("")
            entropy = calculate_entropy("")
            return EvaluationResult(
                length=0,
                score=0,
                strength_level=StrengthLevel.VERY_WEAK,
                entropy=entropy,
                variety=variety,
                patterns=[],
                warnings=["Password cannot be empty."],
                suggestions=[
                    "Create a password with at least 12 to 16 characters.",
                    "Combine uppercase, lowercase, numbers, and special symbols.",
                    "Or use a multi-word passphrase of 4+ random words."
                ],
            )

        # 1. Analyze character variety & entropy
        variety = analyze_character_variety(password)
        entropy = calculate_entropy(password)

        # 2. Detect vulnerability patterns (dictionary, leetspeak, walks, repeats)
        patterns = analyze_all_patterns(password)

        # 3. Calculate baseline score components
        # A. Length score (max 40 points)
        if length < 8:
            length_score = length * 2.5  # Max 17.5 pts
        elif length < 12:
            length_score = 20.0 + (length - 8) * 2.5  # 20.0 to 27.5 pts
        elif length < 16:
            length_score = 30.0 + (length - 12) * 2.5  # 30.0 to 37.5 pts
        else:
            length_score = 40.0

        # B. Variety score (max 30 points)
        variety_score = 0.0
        if variety.has_lowercase:
            variety_score += 6.0
        if variety.has_uppercase:
            variety_score += 7.0
        if variety.has_digits:
            variety_score += 7.0
        if variety.has_symbols:
            variety_score += 10.0

        # Bonus for using all 4 character classes
        if variety.variety_count == 4:
            variety_score += 5.0

        variety_score = min(30.0, variety_score)

        # C. Shannon Entropy score (max 30 points)
        # Shannon entropy per character and total information entropy
        # Typical strong random character entropy: 3.5 - 4.5 bits/char
        per_char_score = min(15.0, (entropy.shannon_entropy_per_char / 4.0) * 15.0)
        # 60+ bits total Shannon entropy is strong
        total_entropy_score = min(15.0, (entropy.total_shannon_entropy / 60.0) * 15.0)
        entropy_score = per_char_score + total_entropy_score

        raw_score = length_score + variety_score + entropy_score

        # 4. Apply pattern penalties
        total_penalty = sum(p.penalty for p in patterns)
        score = max(0.0, raw_score - total_penalty)

        # 5. Apply critical caps and guardrails
        has_critical_dictionary = any(
            p.pattern_type in ("dictionary", "leetspeak") for p in patterns
        )
        all_same_char = variety.unique_char_count <= 1

        if all_same_char:
            score = min(score, 5.0)
        elif has_critical_dictionary:
            score = min(score, 25.0)
        elif length < 8:
            score = min(score, 30.0)
        elif variety.variety_count == 1:
            score = min(score, 35.0)

        final_score = int(round(min(100.0, max(0.0, score))))

        # 6. Map to Strength Level
        if final_score <= 25:
            strength_level = StrengthLevel.VERY_WEAK
        elif final_score <= 50:
            strength_level = StrengthLevel.WEAK
        elif final_score <= 70:
            strength_level = StrengthLevel.MODERATE
        elif final_score <= 85:
            strength_level = StrengthLevel.STRONG
        else:
            strength_level = StrengthLevel.VERY_STRONG

        # 7. Generate Warnings & Actionable Recommendations
        warnings = self._generate_warnings(length, variety, patterns, entropy)
        suggestions = self._generate_suggestions(length, variety, patterns, strength_level)

        return EvaluationResult(
            length=length,
            score=final_score,
            strength_level=strength_level,
            entropy=entropy,
            variety=variety,
            patterns=patterns,
            warnings=warnings,
            suggestions=suggestions,
        )

    def _generate_warnings(
        self,
        length: int,
        variety,
        patterns: List[PatternMatch],
        entropy
    ) -> List[str]:
        warnings: List[str] = []

        if length < 8:
            warnings.append(f"Password is dangerously short ({length} characters). Minimum recommended is 12.")
        elif length < 12:
            warnings.append(f"Password length ({length} characters) is below recommended 12+ standard.")

        if variety.variety_count <= 1:
            warnings.append("Lacks character diversity: composed of only a single character type.")

        for p in patterns:
            if p.severity in ("critical", "high"):
                warnings.append(f"{p.description} (Matched: '{p.matched_text}').")

        if entropy.shannon_entropy_per_char < 2.0 and length >= 4:
            warnings.append(
                f"Low Shannon entropy ({entropy.shannon_entropy_per_char:.2f} bits/symbol): high character predictability."
            )

        return warnings

    def _generate_suggestions(
        self,
        length: int,
        variety,
        patterns: List[PatternMatch],
        strength_level: StrengthLevel
    ) -> List[str]:
        suggestions: List[str] = []

        # Length recommendations
        if length < 12:
            needed = 12 - length
            suggestions.append(f"Extend length: add at least {needed} more characters to reach minimum 12 characters.")
        elif length < 16:
            suggestions.append("Consider extending to 16+ characters for increased cryptographic resistance.")

        # Character variety suggestions
        missing_classes = []
        if not variety.has_lowercase:
            missing_classes.append("lowercase letters (a-z)")
        if not variety.has_uppercase:
            missing_classes.append("uppercase letters (A-Z)")
        if not variety.has_digits:
            missing_classes.append("numbers (0-9)")
        if not variety.has_symbols:
            missing_classes.append("special symbols (e.g. !@#$%^&*)")

        if missing_classes:
            suggestions.append(f"Diversify character set: incorporate {', '.join(missing_classes)}.")

        # Pattern-specific counter-measures
        has_dictionary = any(p.pattern_type in ("dictionary", "dictionary_substring") for p in patterns)
        has_leet = any(p.pattern_type in ("leetspeak", "leetspeak_substring") for p in patterns)
        has_walk = any(p.pattern_type in ("keyboard_walk", "keyboard_diagonal") for p in patterns)
        has_seq = any(p.pattern_type == "sequence" for p in patterns)
        has_rep = any(p.pattern_type in ("repeated_characters", "repeated_chunk") for p in patterns)
        has_year = any(p.pattern_type == "year_pattern" for p in patterns)

        if has_leet:
            suggestions.append(
                "Avoid leetspeak substitutions (e.g. '@' for 'a', '0' for 'o', '1' for 'i'). "
                "Cracking engines easily test leet mutations."
            )
        if has_dictionary and not has_leet:
            suggestions.append("Replace common dictionary words with random character sequences or multi-word passphrases.")
        if has_walk:
            suggestions.append("Eliminate keyboard patterns (e.g. 'qwerty', 'asdf'). They are prioritized by cracking masks.")
        if has_seq:
            suggestions.append("Remove ascending/descending sequences (e.g. '1234', 'abcd').")
        if has_rep:
            suggestions.append("Remove consecutive repeating characters and repeating substring loops.")
        if has_year:
            suggestions.append("Avoid calendar years or birth years, which are standard components in hybrid brute-force dictionaries.")

        # Passphrase recommendation for weaker credentials
        if strength_level in (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK, StrengthLevel.MODERATE):
            suggestions.append(
                "Passphrase alternative: Combine 4+ random, unrelated words separated by hyphens (e.g., 'correct-horse-battery-staple')."
            )

        if not suggestions:
            suggestions.append("Excellent credential! Maintain unique passwords across all distinct services.")

        return suggestions
