"""
Entropy and Character Variety Calculations for Password Auditing.
Implements Shannon Entropy and Theoretical Keyspace Entropy.
"""

import math
import string
from collections import Counter
from src.models import CharacterVariety, EntropyMetrics

# Standard character set pool sizes
POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_SYMBOLS = 33  # Standard ASCII punctuation and whitespace


def analyze_character_variety(password: str) -> CharacterVariety:
    """
    Evaluates the character variety and determines the active pool size.
    """
    if not password:
        return CharacterVariety(
            has_lowercase=False,
            has_uppercase=False,
            has_digits=False,
            has_symbols=False,
            lowercase_count=0,
            uppercase_count=0,
            digit_count=0,
            symbol_count=0,
            unique_char_count=0,
            pool_size=0,
        )

    has_lower = False
    has_upper = False
    has_digits = False
    has_symbols = False
    lower_cnt = 0
    upper_cnt = 0
    digit_cnt = 0
    symbol_cnt = 0
    other_extra = set()

    for ch in password:
        if ch in string.ascii_lowercase:
            has_lower = True
            lower_cnt += 1
        elif ch in string.ascii_uppercase:
            has_upper = True
            upper_cnt += 1
        elif ch in string.digits:
            has_digits = True
            digit_cnt += 1
        elif ch in string.punctuation or ch.isspace():
            has_symbols = True
            symbol_cnt += 1
        else:
            # Extended unicode or other symbols
            has_symbols = True
            symbol_cnt += 1
            other_extra.add(ch)

    pool_size = 0
    if has_lower:
        pool_size += POOL_LOWERCASE
    if has_upper:
        pool_size += POOL_UPPERCASE
    if has_digits:
        pool_size += POOL_DIGITS
    if has_symbols:
        pool_size += POOL_SYMBOLS + len(other_extra)

    unique_chars = len(set(password))

    return CharacterVariety(
        has_lowercase=has_lower,
        has_uppercase=has_upper,
        has_digits=has_digits,
        has_symbols=has_symbols,
        lowercase_count=lower_cnt,
        uppercase_count=upper_cnt,
        digit_count=digit_cnt,
        symbol_count=symbol_cnt,
        unique_char_count=unique_chars,
        pool_size=pool_size,
    )


def calculate_entropy(password: str) -> EntropyMetrics:
    """
    Calculates Shannon Entropy and Theoretical Keyspace Entropy.

    Mathematical formulas:
    1. Shannon Entropy per character:
       H = - sum( p(c) * log2(p(c)) ) for c in unique(password)
       where p(c) = count(c) / length

    2. Total Shannon Entropy (bits):
       E_shannon = length * H

    3. Theoretical Keyspace Entropy (NIST combinatorial search space):
       E_keyspace = length * log2(R)
       where R is the size of the combined character pool used.
    """
    length = len(password)
    if length == 0:
        return EntropyMetrics(
            shannon_entropy_per_char=0.0,
            total_shannon_entropy=0.0,
            keyspace_entropy=0.0,
            pool_size=0,
        )

    variety = analyze_character_variety(password)
    pool_size = variety.pool_size

    # Frequency analysis for Shannon entropy
    counts = Counter(password)
    shannon_per_char = 0.0

    for count in counts.values():
        p = count / length
        shannon_per_char -= p * math.log2(p)

    total_shannon = length * shannon_per_char

    # Theoretical keyspace entropy
    keyspace = length * math.log2(pool_size) if pool_size > 0 else 0.0

    return EntropyMetrics(
        shannon_entropy_per_char=shannon_per_char,
        total_shannon_entropy=total_shannon,
        keyspace_entropy=keyspace,
        pool_size=pool_size,
    )
