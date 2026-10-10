"""
Cryptographically secure password and passphrase generator.
Uses Python's standard `secrets` module (CSPRNG) in volatile memory only.
Also provides attack difficulty estimation based on entropy.
"""

import secrets
import string
from typing import List

# Word pool for XKCD-style memorable passphrases
PASSPHRASE_WORDS: List[str] = [
    "correct", "horse", "battery", "staple", "galaxy", "quantum", "falcon", "anchor",
    "matrix", "vector", "orbital", "shadow", "timber", "canyon", "puzzle", "summit",
    "breeze", "beacon", "glacier", "vortex", "cipher", "planet", "bridge", "copper",
    "silver", "horizon", "echo", "harbor", "zenith", "aurora", "comet", "meteor",
    "stream", "shield", "thunder", "cascade", "prism", "safari", "forest", "desert",
    "cobalt", "granite", "quartz", "willow", "meadow", "island", "valley", "falcon",
    "ember", "feather", "fountain", "harvest", "ignite", "jungle", "lantern", "magnet",
    "nebula", "oasis", "pioneer", "quartz", "radiant", "spiral", "tempest", "voyage"
]


def generate_random_password(
    length: int = 16,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    """
    Generates a cryptographically strong random password using `secrets`.
    Guarantees at least one character from each selected class.
    """
    pools: List[str] = []
    guaranteed: List[str] = []

    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}<>?"
        pools.append(symbols)
        guaranteed.append(secrets.choice(symbols))

    if not pools:
        # Default fallback if nothing selected
        pools.append(string.ascii_letters + string.digits)
        guaranteed.append(secrets.choice(string.ascii_letters))

    all_chars = "".join(pools)
    remaining_length = max(0, length - len(guaranteed))
    random_chars = [secrets.choice(all_chars) for _ in range(remaining_length)]

    combined = guaranteed + random_chars
    # Cryptographically shuffle the characters
    rng = secrets.SystemRandom()
    rng.shuffle(combined)
    return "".join(combined[:length])


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = True
) -> str:
    """
    Generates a multi-word passphrase (XKCD style) from the word pool.
    Easy to remember, extraordinarily high entropy.
    """
    selected = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    if capitalize:
        selected = [w.capitalize() for w in selected]

    phrase = separator.join(selected)
    if include_number:
        num = secrets.randbelow(90) + 10  # 10 to 99
        phrase += f"{separator}{num}"
    return phrase


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimates cracking duration against a high-end offline GPU cracking cluster
    performing approximately 100 billion (10^11) SHA-256 / MD5 hashes per second.
    """
    if entropy_bits <= 0:
        return "Instant (< 1 ms)"

    # Total combinations = 2^entropy_bits
    # Average combinations to test = 2^(entropy_bits - 1)
    # Rate: 100,000,000,000 guesses per second (10^11)
    guesses_per_sec = 1e11

    # In log2 domain:
    # time_sec = 2^(entropy_bits - 1) / 10^11
    # log2(time_sec) = entropy_bits - 1 - log2(10^11)
    # log2(10^11) = 11 * 3.321928 ~ 36.54 bits
    log2_rate = 36.54
    effective_exp = (entropy_bits - 1) - log2_rate

    if effective_exp < -10:
        return "Instant (< 1 millisecond)"
    elif effective_exp < 0:
        seconds = 2 ** effective_exp
        if seconds < 0.1:
            return "Instant (~0.05 seconds)"
        return f"~{seconds:.2f} seconds"
    elif effective_exp < 6:  # up to 64 seconds
        return f"~{int(2 ** effective_exp)} seconds"
    elif effective_exp < 11.8:  # up to ~60 minutes
        minutes = (2 ** effective_exp) / 60
        return f"~{minutes:.1f} minutes"
    elif effective_exp < 16.3:  # up to ~24 hours
        hours = (2 ** effective_exp) / 3600
        return f"~{hours:.1f} hours"
    elif effective_exp < 24.9:  # up to 365 days
        days = (2 ** effective_exp) / 86400
        return f"~{int(days)} days"
    elif effective_exp < 34.8:  # up to 1,000 years
        years = (2 ** effective_exp) / (86400 * 365.25)
        return f"~{int(years):,} years"
    elif effective_exp < 44.8:  # up to 1,000,000 years
        millennia = (2 ** effective_exp) / (86400 * 365.25 * 1000)
        return f"~{int(millennia):,} millennia"
    else:
        return "Trillions of Centuries (Cryptographically Unbreakable)"
