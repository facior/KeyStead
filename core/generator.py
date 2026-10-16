"""
Kryptograficznie bezpieczny generator haseł i haseł wielowyrazowych (passphrases)
oraz analizator siły i entropii hasła.

Ocena siły nie liczy naiwnie "długość × log2(alfabet)" – wykrywa wzorce, od których
zaczynają ataki słownikowe (popularne hasła, słowa, lata, sekwencje, powtórzenia,
zamiany typu p@ssw0rd) i szacuje entropię tak, jak widzi ją atakujący.
"""

import math
import os
import re
import secrets
import string
from functools import lru_cache
from typing import Dict, Any, FrozenSet, List, Tuple

# Zestawy znaków
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS = "0Ool1I|"

_WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist_eff.txt")


@lru_cache(maxsize=1)
def get_wordlist() -> Tuple[str, ...]:
    """Lista EFF Large Wordlist (7776 słów, ~12.9 bita na słowo)."""
    with open(_WORDLIST_PATH, "r", encoding="utf-8") as f:
        words = tuple(line.strip() for line in f if line.strip() and not line.startswith("#"))
    if len(words) < 7776:
        raise RuntimeError("Uszkodzony plik listy słów generatora fraz (wordlist_eff.txt).")
    return words


@lru_cache(maxsize=1)
def _wordset() -> FrozenSet[str]:
    return frozenset(get_wordlist())


BITS_PER_WORD = math.log2(7776)


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True
) -> str:
    """Generuje kryptograficznie bezpieczne losowe hasło o zadanych parametrach."""
    char_pool = ""
    guaranteed = []

    if use_lower:
        chars = [c for c in LOWERCASE if not (avoid_ambiguous and c in AMBIGUOUS)]
        char_pool += "".join(chars)
        guaranteed.append(secrets.choice(chars))

    if use_upper:
        chars = [c for c in UPPERCASE if not (avoid_ambiguous and c in AMBIGUOUS)]
        char_pool += "".join(chars)
        guaranteed.append(secrets.choice(chars))

    if use_digits:
        chars = [c for c in DIGITS if not (avoid_ambiguous and c in AMBIGUOUS)]
        char_pool += "".join(chars)
        guaranteed.append(secrets.choice(chars))

    if use_symbols:
        chars = [c for c in SYMBOLS if not (avoid_ambiguous and c in AMBIGUOUS)]
        char_pool += "".join(chars)
        guaranteed.append(secrets.choice(chars))

    if not char_pool:
        # Fallback jeśli odznaczono wszystko
        char_pool = LOWERCASE + DIGITS
        guaranteed = [secrets.choice(char_pool)]

    if length < len(guaranteed):
        length = len(guaranteed)

    # Dopełnij resztę długości
    remaining = [secrets.choice(char_pool) for _ in range(length - len(guaranteed))]
    all_chars = guaranteed + remaining

    # Bezpieczne przetasowanie (Fisher-Yates z secrets)
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    return "".join(all_chars)


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """
    Generuje łatwe do zapamiętania, silne hasło wielowyrazowe (Diceware, lista EFF).
    5 słów ≈ 64.6 bita, 6 słów ≈ 77.5 bita entropii (+ ~8 bitów za liczbę).
    """
    words = get_wordlist()
    chosen_words = [secrets.choice(words) for _ in range(max(1, word_count))]
    if capitalize:
        chosen_words = [w.capitalize() for w in chosen_words]

    if include_number:
        num = str(secrets.randbelow(90) + 10)
        idx = secrets.randbelow(len(chosen_words))
        chosen_words[idx] += num

    return separator.join(chosen_words)


# --------------------------------------------------------------------- ocena siły

# Najpopularniejsze hasła / rdzenie haseł (PL + EN). Wystarczy dopasowanie fragmentu.
COMMON_PASSWORDS = (
    "password", "passw0rd", "haslo", "haslo1", "qwerty", "qwertyuiop", "azerty", "zaq12wsx", "zaq1",
    "1qaz2wsx", "admin", "administrator", "root", "welcome", "letmein", "login", "master", "secret",
    "dragon", "monkey", "football", "baseball", "soccer", "iloveyou", "princess", "sunshine", "shadow",
    "superman", "batman", "michael", "jennifer", "jordan", "hunter", "killer", "trustno1", "starwars",
    "pokemon", "minecraft", "freedom", "whatever", "computer", "internet", "samsung", "google", "abc123",
    "kocham", "kochamcie", "kochanie", "misiek", "misiaczek", "polska", "polska1", "zaq123", "qazwsx",
    "marcin", "mateusz", "kasia", "agnieszka", "piotr", "tomek", "lukasz", "michal", "krzysiek", "bartek",
    "kacper", "kuba", "ania", "monika", "magda", "karolina", "natalia", "zuzia", "slonko", "skarbie",
    "legia", "lech", "wisla", "barcelona", "liverpool", "arsenal", "chelsea", "juventus", "realmadrid",
    "matrix", "hello", "test", "testing", "summer", "winter", "spring", "autumn", "love", "lovely",
    "flower", "orange", "banana", "cheese", "cookie", "chocolate", "pepper", "ginger", "angel", "lucky",
    "tigger", "charlie", "buster", "maggie", "bailey", "daniel", "thomas", "robert", "andrew", "joshua",
)

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qwertzuiop", "yxcvbnm")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})


def _char_pool_size(password: str) -> int:
    pool = 0
    if any(c in LOWERCASE for c in password):
        pool += 26
    if any(c in UPPERCASE for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any((not c.isalnum()) and ord(c) < 128 for c in password):
        pool += 33
    if any(ord(c) > 127 for c in password):
        pool += 50
    return max(pool, 1)


def calculate_entropy(password: str) -> float:
    """Naiwna górna granica entropii (długość × log2 alfabetu) – tylko informacyjnie."""
    if not password:
        return 0.0
    return len(password) * math.log2(_char_pool_size(password))


def _passphrase_bits(password: str) -> float:
    """Jeśli hasło to fraza ze słów listy EFF, zwraca jej entropię; w przeciwnym razie 0."""
    tokens = [t for t in re.split(r"[\s\-_.,;:+/]+", password) if t]
    if len(tokens) < 3:
        return 0.0
    words = _wordset()
    bits = 0.0
    for tok in tokens:
        core = re.sub(r"\d+$", "", tok).lower()
        if core not in words:
            return 0.0
        bits += BITS_PER_WORD
        if core != tok.lower():
            bits += 3.3  # dopisana liczba
    return bits


def _find_patterns(password: str) -> List[Tuple[int, int, float, str]]:
    """Zwraca listę dopasowań (start, koniec, bity, opis) dla przewidywalnych fragmentów."""
    lower = password.lower()
    leet = lower.translate(_LEET)
    found: List[Tuple[int, int, float, str]] = []

    # 1. Popularne hasła (także w wersji leet)
    for word in sorted(set(COMMON_PASSWORDS), key=len, reverse=True):
        for text in (lower, leet):
            start = text.find(word)
            while start != -1:
                seg = password[start:start + len(word)]
                bits = math.log2(len(COMMON_PASSWORDS)) + (1 if any(c.isupper() for c in seg) else 0) + (1 if text is leet and seg.lower() != word else 0)
                found.append((start, start + len(word), bits, "popularne hasło"))
                start = text.find(word, start + 1)

    # 2. Słowa ze słownika (min. 4 litery)
    words = _wordset()
    n = len(lower)
    for i in range(n):
        for j in range(min(n, i + 12), i + 3, -1):
            if leet[i:j] in words or lower[i:j] in words:
                found.append((i, j, BITS_PER_WORD + (1 if any(c.isupper() for c in password[i:j]) else 0), "słowo"))
                break

    # 3. Lata i daty
    for m in re.finditer(r"(19|20)\d{2}", password):
        found.append((m.start(), m.end(), 6.6, "rok"))

    # 4. Sekwencje: abcd, 4321, qwerty, asdf...
    def _is_seq(a: str, b: str) -> bool:
        if abs(ord(b) - ord(a)) == 1 and a.isalnum() and b.isalnum():
            return True
        return any(a + b in row or b + a in row for row in _KEYBOARD_ROWS)

    i = 0
    while i < n - 1:
        j = i
        while j + 1 < n and _is_seq(lower[j], lower[j + 1]):
            j += 1
        if j - i + 1 >= 3:
            found.append((i, j + 1, 4.0 + math.log2(j - i + 1), "sekwencja"))
            i = j + 1
        else:
            i += 1

    # 5. Powtórzenia: aaaa, abcabc
    for m in re.finditer(r"(.+?)\1{2,}|(.{2,}?)\2+", password):
        unit = m.group(1) or m.group(2)
        found.append((m.start(), m.end(), len(unit) * math.log2(_char_pool_size(unit)) + math.log2(len(m.group(0)) / len(unit) + 1), "powtórzenie"))

    return found


def _estimate_bits(password: str) -> float:
    """Szacuje entropię z perspektywy atakującego: najtańsze pokrycie hasła wzorcami."""
    pool_bits = math.log2(_char_pool_size(password))
    n = len(password)
    patterns = _find_patterns(password)
    # Programowanie dynamiczne: minimalna liczba bitów do "zgadnięcia" prefiksu długości i
    best = [0.0] + [math.inf] * n
    for i in range(n):
        if best[i] == math.inf:
            continue
        best[i + 1] = min(best[i + 1], best[i] + pool_bits)
        for start, end, bits, _ in patterns:
            if start == i:
                best[end] = min(best[end], best[i] + bits)
    matched = sum(1 for p in patterns if p[3] in ("popularne hasło", "słowo"))
    # Atakujący musi też zgadnąć strukturę (kolejność i liczbę elementów)
    return best[n] + (math.log2(matched + 1) if matched else 0.0)


def evaluate_password_strength(password: str) -> Dict[str, Any]:
    """
    Analizuje siłę hasła, oblicza ocenę (0-4), szacowaną entropię oraz zalecenia.
    Skala: <28 bitów bardzo słabe, <45 słabe, <60 średnie, <75 silne, ≥75 bardzo silne.
    """
    if not password:
        return {
            "score": 0,
            "label": "Brak hasła",
            "color": "#e74c3c",
            "entropy": 0.0,
            "feedback": ["Wprowadź hasło."]
        }

    # Fraza ze słownika: atakujący zgaduje słowa, nie pojedyncze znaki
    phrase_bits = _passphrase_bits(password)
    entropy = phrase_bits if phrase_bits else _estimate_bits(password)
    feedback = []

    if entropy < 28:
        score = 0
    elif entropy < 45:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 75:
        score = 3
    else:
        score = 4

    labels = {
        0: ("Bardzo słabe", "#e74c3c"),
        1: ("Słabe", "#e67e22"),
        2: ("Średnie", "#f1c40f"),
        3: ("Silne", "#2ecc71"),
        4: ("Bardzo silne", "#27ae60")
    }

    kinds = {p[3] for p in _find_patterns(password)} if not phrase_bits else set()
    if phrase_bits and score < 3:
        feedback.append("Fraza ma za mało słów – użyj co najmniej 5 losowych słów.")
    if "popularne hasło" in kinds:
        feedback.append("Zawiera popularne hasło – jest w słownikach ataków.")
    if "rok" in kinds:
        feedback.append("Lata i daty łatwo zgadnąć.")
    if "sekwencja" in kinds or "powtórzenie" in kinds:
        feedback.append("Unikaj sekwencji (abc, 123, qwerty) i powtórzeń.")
    if score < 3 and len(password) < 14:
        feedback.append("Wydłuż hasło – najlepiej do 16+ losowych znaków lub 5-6 losowych słów.")

    label, color = labels[score]
    return {
        "score": score,
        "label": label,
        "color": color,
        "entropy": round(entropy, 1),
        "feedback": feedback
    }


MASTER_MIN_LENGTH = 10


def check_master_password(password: str) -> Tuple[bool, str]:
    """
    Polityka hasła głównego. Zwraca (dozwolone, komunikat):
    - (False, błąd)       – hasło zbyt słabe, nie wolno go użyć,
    - (True, ostrzeżenie) – hasło średnie, warto potwierdzić świadomie,
    - (True, "")          – hasło silne.
    """
    if len(password) < MASTER_MIN_LENGTH:
        return False, f"Hasło główne musi mieć co najmniej {MASTER_MIN_LENGTH} znaków."
    res = evaluate_password_strength(password)
    if res["score"] < 2:
        hint = " ".join(res["feedback"])
        return False, f"Hasło główne jest zbyt słabe ({res['label']}, ~{res['entropy']} bitów). {hint}".strip()
    if res["score"] == 2:
        return True, (
            f"Hasło główne ma średnią siłę (~{res['entropy']} bitów). Jeśli ktoś przechwyci plik sejfu, "
            "będzie mógł próbować łamać je offline. Zalecamy frazę z 5-6 losowych słów."
        )
    return True, ""
