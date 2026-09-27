"""Classical ciphers: encrypt, decrypt and (where possible) break.

Educational only — every cipher here is broken by modern standards. The
point is to make the attacks runnable and visible.
"""
import string

ALPHABET = string.ascii_lowercase


class CipherError(ValueError):
    pass


def _letters_only(text):
    return [ch for ch in text.lower() if ch in ALPHABET]


def _preserve_shape(cipher_chars, original):
    """Map computed letters back onto the original's case and spacing."""
    out = []
    iterator = iter(cipher_chars)
    for ch in original:
        if ch.lower() in ALPHABET:
            c = next(iterator)
            out.append(c.upper() if ch.isupper() else c)
        else:
            out.append(ch)
    return "".join(out)


def caesar(text, shift):
    """Caesar shift: ROT-N over the 26-letter alphabet."""
    if not 0 <= shift < 26:
        raise CipherError(f"shift must be 0..25, got {shift}")
    letters = _letters_only(text)
    shifted = [ALPHABET[(ALPHABET.index(ch) + shift) % 26] for ch in letters]
    return _preserve_shape(shifted, text)


def caesar_decrypt(text, shift):
    return caesar(text, -shift % 26)


def atbash(text):
    """Atbash: a<->z, b<->y, ... (its own inverse)."""
    letters = _letters_only(text)
    mapped = [ALPHABET[25 - ALPHABET.index(ch)] for ch in letters]
    return _preserve_shape(mapped, text)


def vigenere(text, key, decrypt=False):
    """Vigenere with the classic A=0 convention."""
    if not key:
        raise CipherError("key must not be empty")
    key_letters = _letters_only(key)
    if not key_letters:
        raise CipherError("key has no letters")
    letters = _letters_only(text)
    out = []
    for i, ch in enumerate(letters):
        k = ALPHABET.index(key_letters[i % len(key_letters)])
        base = ALPHABET.index(ch)
        out.append(ALPHABET[(base - k) % 26 if decrypt else (base + k) % 26])
    return _preserve_shape(out, text)


def rail_fence(text, rails, decrypt=False):
    """Rail fence (zig-zag) transposition."""
    if rails < 2:
        raise CipherError("need at least 2 rails")
    letters = _letters_only(text)
    if not letters:
        return text
    n = len(letters)
    if rails >= n:
        return "".join(letters) if not decrypt else "".join(letters)

    # build the zig-zag pattern of rail indices
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    if not decrypt:
        rails_content = [[] for _ in range(rails)]
        for ch, r in zip(letters, pattern):
            rails_content[r].append(ch)
        return _preserve_shape([ch for row in rails_content for ch in row], text)

    counts = [pattern.count(r) for r in range(rails)]
    rails_content = []
    index = 0
    for count in counts:
        rails_content.append(list(letters[index:index + count]))
        index += count
    plain = []
    for r in pattern:
        plain.append(rails_content[r].pop(0))
    return _preserve_shape(plain, text)


def _check_substitution_key(key_letters):
    if len(key_letters) != 26:
        raise CipherError("substitution key must be 26 letters")
    if sorted(key_letters) != sorted(ALPHABET):
        raise CipherError("substitution key must be a permutation of a-z")


def substitution_decrypt(text, key_letters):
    """Decrypt a simple substitution: key_letters[i] is the ciphertext
    letter standing in for plaintext ALPHABET[i]."""
    _check_substitution_key(key_letters)
    mapping = {key_letters[i]: ALPHABET[i] for i in range(26)}
    letters = _letters_only(text)
    return _preserve_shape([mapping[ch] for ch in letters], text)


def substitution_encrypt(text, key_letters):
    _check_substitution_key(key_letters)
    mapping = {ALPHABET[i]: key_letters[i] for i in range(26)}
    letters = _letters_only(text)
    return _preserve_shape([mapping[ch] for ch in letters], text)


def xor(data, key):
    """Repeating-key XOR — the toy version of a stream cipher.

    Accepts str or bytes and returns the same type, so it composes with
    itself: xor(xor(x, k), k) == x.
    """
    if not key:
        raise CipherError("key must not be empty")
    was_text = isinstance(data, str)
    raw = data.encode("utf-8") if was_text else bytes(data)
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return out.decode("utf-8", "replace") if was_text else out


CIPHERS = {
    "caesar": "ROT-N over the alphabet",
    "atbash": "a<->z mirror (self-inverse)",
    "vigenere": "polyalphabetic with a repeating key",
    "railfence": "zig-zag transposition",
    "substitution": "monoalphabetic substitution with a 26-letter key",
    "xor": "repeating-key XOR over bytes",
}
