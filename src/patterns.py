"""
Pattern and Weakness Detection for Password Auditing.
Detects:
- Dictionary words and breached credentials
- Leetspeak and weak character substitutions (e.g., 'p@ssword')
- Predictable sequences (numeric and alphabetic)
- Keyboard walks (QWERTY horizontal and diagonal)
- Repeated characters and recurring chunk patterns
- Common 4-digit year patterns
"""

import re
from typing import List, Tuple
from src.models import PatternMatch
from src.dictionaries import COMMON_PASSWORDS_AND_WORDS

# Common leetspeak translation mappings
LEET_MAPPINGS = {
    '@': 'a',
    '4': 'a',
    '8': 'b',
    '(': 'c',
    '<': 'c',
    '3': 'e',
    '1': 'i',
    '!': 'i',
    '|': 'i',
    '0': 'o',
    '$': 's',
    '5': 's',
    '7': 't',
    '+': 't',
    '2': 'z',
    '9': 'g',
}

# Keyboard layout rows (lowercase)
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Common keyboard diagonals (top to bottom and bottom to top)
KEYBOARD_DIAGONALS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/",
    "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7"
]


def normalize_leetspeak(text: str) -> str:
    """
    Translates common leetspeak substitutions to standard lowercase letters.
    Example: 'P@55w0rd' -> 'password', '4dm1n' -> 'admin'.
    """
    chars = []
    for ch in text.lower():
        chars.append(LEET_MAPPINGS.get(ch, ch))
    return "".join(chars)


def detect_dictionary_and_leetspeak(password: str) -> List[PatternMatch]:
    """
    Checks for exact or embedded common dictionary words and leetspeak substitutions.
    """
    matches: List[PatternMatch] = []
    lower_pwd = password.lower()
    leet_norm = normalize_leetspeak(password)
    detected_words = set()

    # 1. Exact match on raw password
    if lower_pwd in COMMON_PASSWORDS_AND_WORDS:
        matches.append(
            PatternMatch(
                pattern_type="dictionary",
                matched_text=password,
                description=f"Exact match with common dictionary word / breached credential '{lower_pwd}'",
                severity="critical",
                penalty=45.0,
            )
        )
        detected_words.add(lower_pwd)

    # 2. Exact match on leetspeak normalized password
    elif leet_norm in COMMON_PASSWORDS_AND_WORDS:
        matches.append(
            PatternMatch(
                pattern_type="leetspeak",
                matched_text=password,
                description=f"Weak leetspeak substitution of common word '{leet_norm}' (e.g. '@' for 'a', '0' for 'o')",
                severity="critical",
                penalty=40.0,
            )
        )
        detected_words.add(leet_norm)

    # 3. Substring search for dictionary words (min length 4)
    for word in COMMON_PASSWORDS_AND_WORDS:
        if len(word) < 4:
            continue
        if word in detected_words:
            continue

        # Substring in raw lowercase
        if word in lower_pwd:
            idx = lower_pwd.find(word)
            matched_segment = password[idx:idx + len(word)]
            matches.append(
                PatternMatch(
                    pattern_type="dictionary_substring",
                    matched_text=matched_segment,
                    description=f"Contains common dictionary word '{word}'",
                    severity="high",
                    penalty=25.0,
                )
            )
            detected_words.add(word)
        # Substring in leet normalized
        elif word in leet_norm:
            idx = leet_norm.find(word)
            matched_segment = password[idx:idx + len(word)]
            matches.append(
                PatternMatch(
                    pattern_type="leetspeak_substring",
                    matched_text=matched_segment,
                    description=f"Contains leetspeak-disguised word '{word}' (matched '{matched_segment}')",
                    severity="high",
                    penalty=25.0,
                )
            )
            detected_words.add(word)

    return matches


def detect_sequential_patterns(password: str) -> List[PatternMatch]:
    """
    Detects predictable sequential characters (numeric and alphabetic) of length 3 or more.
    e.g. '123456', '654321', 'abcdef', 'fedcba'.
    """
    matches: List[PatternMatch] = []
    if len(password) < 3:
        return matches

    lower_pwd = password.lower()
    n = len(lower_pwd)
    i = 0

    while i < n - 2:
        # Check ascending sequence
        run_len = 1
        diff = ord(lower_pwd[i + 1]) - ord(lower_pwd[i])

        if diff in (1, -1) and (
            (lower_pwd[i].isdigit() and lower_pwd[i + 1].isdigit()) or
            (lower_pwd[i].isalpha() and lower_pwd[i + 1].isalpha())
        ):
            j = i + 1
            while j < n and (
                (lower_pwd[j].isdigit() and lower_pwd[j - 1].isdigit()) or
                (lower_pwd[j].isalpha() and lower_pwd[j - 1].isalpha())
            ) and (ord(lower_pwd[j]) - ord(lower_pwd[j - 1]) == diff):
                run_len += 1
                j += 1

            if run_len >= 3:
                seq = password[i:i + run_len]
                direction = "ascending" if diff == 1 else "descending"
                category = "numeric" if seq[0].isdigit() else "alphabetical"
                matches.append(
                    PatternMatch(
                        pattern_type="sequence",
                        matched_text=seq,
                        description=f"Predictable {direction} {category} sequence '{seq}' detected",
                        severity="high" if run_len >= 4 else "medium",
                        penalty=15.0 + min(15.0, (run_len - 3) * 5.0),
                    )
                )
                i += run_len
                continue
        i += 1

    return matches


def detect_keyboard_walks(password: str) -> List[PatternMatch]:
    """
    Detects contiguous keyboard walks along QWERTY rows and diagonals of length 3 or more.
    e.g. 'qwerty', 'asdfg', '1qaz'.
    """
    matches: List[PatternMatch] = []
    if len(password) < 3:
        return matches

    lower_pwd = password.lower()

    # 1. Check keyboard rows (forward and reverse)
    checked_spans: List[Tuple[int, int]] = []
    for row in KEYBOARD_ROWS:
        rev_row = row[::-1]
        for pattern in (row, rev_row):
            for length in range(len(pattern), 2, -1):
                for start in range(len(pattern) - length + 1):
                    sub = pattern[start:start + length]
                    pos = lower_pwd.find(sub)
                    while pos != -1:
                        end = pos + length
                        # Check if overlapping already matched span
                        if not any(s <= pos and end <= e for s, e in checked_spans):
                            matched_text = password[pos:end]
                            matches.append(
                                PatternMatch(
                                    pattern_type="keyboard_walk",
                                    matched_text=matched_text,
                                    description=f"Predictable keyboard walk sequence '{matched_text}' detected",
                                    severity="high" if length >= 4 else "medium",
                                    penalty=15.0 + min(20.0, (length - 3) * 5.0),
                                )
                            )
                            checked_spans.append((pos, end))
                        pos = lower_pwd.find(sub, pos + 1)

    # 2. Check diagonals
    for diag in KEYBOARD_DIAGONALS:
        if diag in lower_pwd:
            pos = lower_pwd.find(diag)
            end = pos + len(diag)
            if not any(s <= pos and end <= e for s, e in checked_spans):
                matched_text = password[pos:end]
                matches.append(
                    PatternMatch(
                        pattern_type="keyboard_diagonal",
                        matched_text=matched_text,
                        description=f"Keyboard diagonal sequence '{matched_text}' detected",
                        severity="medium",
                        penalty=15.0,
                    )
                )
                checked_spans.append((pos, end))

    return matches


def detect_repeated_patterns(password: str) -> List[PatternMatch]:
    """
    Detects repeated single characters (e.g. 'aaaa', '1111')
    and repeated substring chunks (e.g. 'abcabc', 'passpass', '1212').
    """
    matches: List[PatternMatch] = []
    if len(password) < 3:
        return matches

    # 1. Repeated consecutive identical characters (3 or more)
    consecutive_re = re.compile(r'(.)\1{2,}')
    for m in consecutive_re.finditer(password):
        matched_str = m.group(0)
        matches.append(
            PatternMatch(
                pattern_type="repeated_characters",
                matched_text=matched_str,
                description=f"Repeated character '{m.group(1)}' repeated {len(matched_str)} times consecutively",
                severity="high" if len(matched_str) >= 4 else "medium",
                penalty=10.0 + min(15.0, (len(matched_str) - 2) * 5.0),
            )
        )

    # 2. Repeated multi-character chunks (e.g. 'abcabc', 'toktok')
    chunk_re = re.compile(r'(.{2,8}?)\1+')
    for m in chunk_re.finditer(password):
        chunk = m.group(1)
        full_match = m.group(0)
        # Avoid duplicate flagging if chunk is just identical single chars handled above
        if len(set(chunk)) > 1 and len(full_match) >= 4:
            repeat_count = len(full_match) // len(chunk)
            matches.append(
                PatternMatch(
                    pattern_type="repeated_chunk",
                    matched_text=full_match,
                    description=f"Predictable recurring chunk pattern '{chunk}' repeated {repeat_count} times",
                    severity="high",
                    penalty=20.0,
                )
            )

    return matches


def detect_year_patterns(password: str) -> List[PatternMatch]:
    """
    Detects 4-digit years between 1920 and 2035 (e.g., 'Summer2023').
    """
    matches: List[PatternMatch] = []
    year_re = re.compile(r'(19[2-9]\d|20[0-3]\d)')
    for m in year_re.finditer(password):
        year_str = m.group(0)
        matches.append(
            PatternMatch(
                pattern_type="year_pattern",
                matched_text=year_str,
                description=f"Contains common 4-digit calendar year '{year_str}'",
                severity="low",
                penalty=10.0,
            )
        )
    return matches


def analyze_all_patterns(password: str) -> List[PatternMatch]:
    """
    Runs all pattern analyzers and aggregates identified weaknesses.
    """
    patterns: List[PatternMatch] = []
    patterns.extend(detect_dictionary_and_leetspeak(password))
    patterns.extend(detect_sequential_patterns(password))
    patterns.extend(detect_keyboard_walks(password))
    patterns.extend(detect_repeated_patterns(password))
    patterns.extend(detect_year_patterns(password))
    return patterns
