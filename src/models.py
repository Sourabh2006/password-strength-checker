"""
Data models for the Password Strength Checker.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any


class StrengthLevel(str, Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"

    @property
    def color_code(self) -> str:
        """ANSI color codes for terminal display."""
        mapping = {
            StrengthLevel.VERY_WEAK: "\033[91m",    # Red
            StrengthLevel.WEAK: "\033[31m",         # Light Red / Orange-Red
            StrengthLevel.MODERATE: "\033[93m",     # Yellow
            StrengthLevel.STRONG: "\033[92m",       # Green
            StrengthLevel.VERY_STRONG: "\033[96m",  # Cyan / Bright Green
        }
        return mapping.get(self, "\033[0m")


@dataclass
class CharacterVariety:
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    lowercase_count: int
    uppercase_count: int
    digit_count: int
    symbol_count: int
    unique_char_count: int
    pool_size: int

    @property
    def variety_count(self) -> int:
        return sum([
            self.has_lowercase,
            self.has_uppercase,
            self.has_digits,
            self.has_symbols
        ])


@dataclass
class EntropyMetrics:
    shannon_entropy_per_char: float  # Bits per character: H = -sum(p * log2(p))
    total_shannon_entropy: float     # Total bits: L * H
    keyspace_entropy: float          # Theoretical keyspace bits: L * log2(pool_size)
    pool_size: int                   # Size of active character set pool


@dataclass
class PatternMatch:
    pattern_type: str       # e.g., 'dictionary', 'leetspeak', 'keyboard_walk', 'repetition', 'sequence'
    matched_text: str       # Substring or representation of matched pattern
    description: str        # Explanation of the weakness
    severity: str           # 'critical', 'high', 'medium', 'low'
    penalty: float          # Score deduction points


@dataclass
class EvaluationResult:
    length: int
    score: int                             # 0 - 100
    strength_level: StrengthLevel
    entropy: EntropyMetrics
    variety: CharacterVariety
    patterns: List[PatternMatch] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation result to a dictionary (never includes original raw password)."""
        return {
            "length": self.length,
            "score": self.score,
            "strength_level": self.strength_level.value,
            "entropy": {
                "shannon_entropy_per_char": round(self.entropy.shannon_entropy_per_char, 2),
                "total_shannon_entropy": round(self.entropy.total_shannon_entropy, 2),
                "keyspace_entropy": round(self.entropy.keyspace_entropy, 2),
                "pool_size": self.entropy.pool_size,
            },
            "variety": {
                "has_lowercase": self.variety.has_lowercase,
                "has_uppercase": self.variety.has_uppercase,
                "has_digits": self.variety.has_digits,
                "has_symbols": self.variety.has_symbols,
                "variety_count": self.variety.variety_count,
            },
            "patterns_detected": [
                {
                    "type": p.pattern_type,
                    "matched": p.matched_text,
                    "description": p.description,
                    "severity": p.severity,
                }
                for p in self.patterns
            ],
            "warnings": self.warnings,
            "suggestions": self.suggestions,
        }
