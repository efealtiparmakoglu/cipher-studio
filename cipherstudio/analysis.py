"""Cryptanalysis: frequency tables, index of coincidence, key-length
estimation and the actual attacks used by cipher-studio."""
import math
import string
from collections import Counter

from .ciphers import (ALPHABET, CipherError, _preserve_shape, caesar_decrypt,
                      substitution_decrypt, vigenere)

# Relative letter frequencies of English prose (percent).
ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

COMMON_WORDS = ("the", "and", "that", "have", "for", "not", "with", "you",
                "this", "but", "his", "from", "they", "which", "were")

# The 50 most frequent English bigrams. On a nine-letter Vigenere stream
# letter frequencies are noise; letter *pairs* still leak the plaintext.
COMMON_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se
ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur
""".split())


def letters_only(text):
    return [ch.lower() for ch in text if ch.lower() in ALPHABET]


def frequency(text):
    """Count and percentage of each letter in the text."""
    letters = letters_only(text)
    counts = Counter(letters)
    total = len(letters) or 1
    return {ch: counts.get(ch, 0) for ch in ALPHABET}, {
        ch: counts.get(ch, 0) * 100.0 / total for ch in ALPHABET
    }


def index_of_coincidence(text):
    """Probability that two random letters of the text match.

    English prose sits near 0.065; random text sits near 0.038.
    """
    letters = letters_only(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_squared(observed_percent, expected=ENGLISH_FREQ):
    """Lower is better: how far a distribution sits from English."""
    total = sum(observed_percent.values()) or 1.0
    score = 0.0
    for ch in ALPHABET:
        expected_count = expected[ch] / 100.0 * total
        if expected_count == 0:
            continue
        score += (observed_percent[ch] - expected_count) ** 2 / expected_count
    return score


def bigram_score(text):
    """Fraction of adjacent letter pairs that are common English bigrams."""
    letters = letters_only(text)
    if len(letters) < 2:
        return 0.0
    pairs = [letters[i] + letters[i + 1] for i in range(len(letters) - 1)]
    hits = sum(1 for pair in pairs if pair in COMMON_BIGRAMS)
    return hits / len(pairs)


def english_score(text):
    """Heuristic 0..1: how English does this text look?

    Bigrams carry the most weight because they survive on the short
    fragments a Vigenere break works with; words only help when present.
    """
    letters = letters_only(text)
    if not letters:
        return 0.0
    words = [w for w in _words(text) if w]
    word_hits = sum(1 for w in words if w in COMMON_WORDS)
    word_score = (word_hits / len(words)) if words else 0.0

    ic = index_of_coincidence(text)
    ic_score = max(0.0, min(1.0, (ic - 0.035) / 0.035))  # 0.035 -> 0, 0.07 -> 1

    _, percents = frequency(text)
    chi = chi_squared(percents)
    # measured: English prose lands under 30, garbled text in the thousands
    chi_score = max(0.0, min(1.0, 1.0 - chi / 250.0))

    bigrams = bigram_score(text)
    # measured: English prose runs near 0.5 common bigrams, random text
    # near 0.06 — 0.4 is the midpoint the saturation is centred on
    bigram_score_saturated = min(1.0, bigrams / 0.40)

    return (0.35 * bigram_score_saturated + 0.30 * chi_score +
            0.15 * ic_score + 0.20 * min(1.0, word_score * 4))


def _words(text):
    cleaned = "".join(ch if ch.isalnum() else " " for ch in text.lower())
    return cleaned.split()


def kasiski_spacings(ciphertext, keyword="the"):
    """Distances between repeated sequences — a Vigenère key-length hint."""
    letters = letters_only(ciphertext)
    positions = {}
    spacings = []
    span = len(keyword)
    for i in range(len(letters) - span):
        chunk = "".join(letters[i:i + span])
        if chunk in positions:
            spacings.append(i - positions[chunk])
        positions[chunk] = i
    return spacings


def guess_key_lengths(ciphertext, max_length=20):
    """Rank candidate Vigenere key lengths using IC per stream."""
    letters = letters_only(ciphertext)
    if len(letters) < 20:
        return []
    candidates = []
    for length in range(1, max_length + 1):
        ics = []
        for offset in range(length):
            stream = letters[offset::length]
            if len(stream) >= 4:
                ics.append(index_of_coincidence("".join(stream)))
        if not ics:
            continue
        average = sum(ics) / len(ics)
        candidates.append((length, average))
    # a real key's streams look English; random ones sit near 0.038
    candidates.sort(key=lambda pair: -pair[1])
    return candidates


def break_caesar(ciphertext):
    """Try all 26 shifts, return the most English-looking plaintext."""
    best = None
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        score = english_score(candidate)
        if best is None or score > best[1]:
            best = (candidate, score, shift)
    return {"plaintext": best[0], "score": best[1], "shift": best[2]}


def break_caesar_with_known_plaintext(ciphertext, known="the"):
    """Known-plaintext attack: crib dragging over all 26 shifts."""
    crib = "".join(ch for ch in known.lower() if ch in ALPHABET)
    if not crib:
        raise CipherError("known plaintext needs letters")
    results = []
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        if crib in candidate.lower():
            results.append({"shift": shift, "plaintext": candidate})
    return results


def break_vigenere(ciphertext, key_length=None):
    """Break a Vigenere by splitting into streams and solving each Caesar."""
    letters = letters_only(ciphertext)
    if not letters:
        return {"plaintext": "", "key": "", "key_length": 0}

    if key_length is None:
        ranked = guess_key_lengths(ciphertext)
        if not ranked:
            raise CipherError("ciphertext too short to estimate a key")
        key_length = ranked[0][0]

    key = []
    for offset in range(key_length):
        stream = "".join(letters[offset::key_length])
        best_shift, best_score = 0, -1.0
        for shift in range(26):
            candidate = "".join(
                ALPHABET[(ALPHABET.index(ch) - shift) % 26] for ch in stream)
            score = english_score(candidate)
            if score > best_score:
                best_score, best_shift = score, shift
        key.append(chr(ord("a") + best_shift))

    plaintext = vigenere(ciphertext, "".join(key), decrypt=True)
    return {
        "plaintext": plaintext,
        "key": "".join(key),
        "key_length": key_length,
        "score": english_score(plaintext),
    }


# Substitution search works on a bounded sample: the statistics settle
# long before the end of a long text, and this keeps the break fast.
SUBSTITUTION_SAMPLE = 600


def _apply_mapping(text, mapping):
    """Decrypt with an arbitrary cipher->plain mapping (no permutation check)."""
    letters = letters_only(text)
    return _preserve_shape([mapping[ch] for ch in letters], text)


def break_substitution(ciphertext, restarts=8, seed=1, passes=12):
    """Recover a monoalphabetic substitution key, approximately.

    The classical attack, in its honest form: pair the most frequent
    ciphertext letters with the most frequent English ones, then hill
    climb by swapping pairs of mappings, keeping swaps that make the
    decryption look more English. A few restarts shake off bad starts.

    This is a heuristic, not a proof. Letter frequencies, common
    bigrams and word hits cannot separate two rare letters, so on
    ordinary-length English the result usually lands a few letters
    short — the same limitation real frequency cryptanalysis has
    without a quadgram model. The printed plaintext is meant to be
    finished by eye. Deterministic: the seed fixes every choice.
    """
    import random

    sample = letters_only(ciphertext)[:SUBSTITUTION_SAMPLE]
    if not sample:
        return {"plaintext": "", "key": "", "score": 0.0}

    english_order = [ch for ch, _ in
                     Counter("etaoinshrdlcumwfgypbvkjxqz").most_common()]

    def score_mapping(mapping):
        return english_score(_apply_mapping(ciphertext, mapping))

    counts = Counter(sample)
    rng = random.Random(seed)
    best_mapping, best_score = None, -1.0

    for attempt in range(restarts):
        # rank pairing: the most frequent ciphertext letter almost surely
        # stands for E, the next for T, and so on
        cipher_order = [ch for ch, _ in counts.most_common()]
        cipher_order += [ch for ch in ALPHABET if ch not in cipher_order]
        plain_pool = list(english_order)
        if attempt:
            rng.shuffle(plain_pool)  # later restarts start from fresh guesses
        mapping = dict(zip(cipher_order, plain_pool))

        current_score = score_mapping(mapping)
        for _pass in range(passes):
            improved = False
            for i in range(26):
                for j in range(i + 1, 26):
                    key_i, key_j = ALPHABET[i], ALPHABET[j]
                    mapping[key_i], mapping[key_j] = mapping[key_j], mapping[key_i]
                    trial_score = score_mapping(mapping)
                    if trial_score > current_score:
                        current_score = trial_score
                        improved = True
                    else:
                        mapping[key_i], mapping[key_j] = mapping[key_j], mapping[key_i]
            if not improved:
                break

        if current_score > best_score:
            best_mapping, best_score = dict(mapping), current_score
        if best_score > 0.97:
            break

    # the public key format is plaintext -> ciphertext, the inverse of the
    # cipher -> plaintext mapping the search works with
    inverse = {plain: cipher for cipher, plain in best_mapping.items()}
    key = "".join(inverse[ch] for ch in ALPHABET)
    return {
        "plaintext": substitution_decrypt(ciphertext, key),
        "key": key,
        "score": best_score,
    }


def frequency_chart(text, width=40):
    """An ASCII histogram of letter frequencies."""
    counts, percents = frequency(text)
    highest = max(percents.values()) or 1.0
    lines = []
    for ch in ALPHABET:
        bar = "#" * int(round(width * percents[ch] / highest))
        lines.append(f"{ch} {counts[ch]:5d} {percents[ch]:6.2f}% |{bar}")
    lines.append(f"   total letters: {sum(counts.values())}")
    return "\n".join(lines)
