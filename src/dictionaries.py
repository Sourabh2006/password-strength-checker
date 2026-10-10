"""
Curated list of common passwords, leaked credentials, and dictionary root words.
All stored as lowercase strings for fast O(1) set lookup.
"""

COMMON_PASSWORDS_AND_WORDS = {
    # Top leaked and generic passwords
    "password", "passcode", "pass", "admin", "administrator", "root", "guest", "default",
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm", "123456", "12345678",
    "123456789", "1234567890", "000000", "111111", "welcome", "welcome1", "login",
    "letmein", "access", "secret", "master", "trustno1", "security", "support",
    "system", "service", "computer", "network", "server", "database", "operator",

    # Common names and relationships
    "iloveyou", "iloveu", "love", "lover", "sweetheart", "baby", "princess", "prince",
    "queen", "king", "michael", "daniel", "jessica", "charlie", "thomas", "robert",
    "david", "john", "james", "william", "alexander", "emma", "olivia", "sophia",
    "george", "jordan", "joshua", "andrew", "hunter", "hunter2", "shadow",

    # Pop culture and entertainment
    "superman", "batman", "spiderman", "ironman", "matrix", "starwars", "pokemon",
    "naruto", "dragon", "wizard", "ninja", "monkey", "tiger", "lion", "elephant",
    "monster", "cookie", "coffee", "cheese", "banana", "apple", "orange",

    # Sports and hobbies
    "football", "baseball", "basketball", "soccer", "liverpool", "chelsea",
    "arsenal", "barcelona", "madrid", "champion", "winner", "player",

    # Seasons, months, days
    "summer", "winter", "spring", "autumn", "fall", "january", "february", "march",
    "april", "may", "june", "july", "august", "september", "october", "november",
    "december", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",

    # Everyday vocabulary roots
    "sunshine", "sunny", "day", "night", "flower", "garden", "house", "home", "family", "friend",
    "school", "college", "office", "work", "money", "dollar", "wealth",
    "happy", "smile", "peace", "freedom", "heaven", "angel", "magic",
    "simple", "easy", "basic", "testing", "sample", "demo", "temp", "temporary"
}
