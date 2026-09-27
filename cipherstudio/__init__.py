"""cipher-studio — classical ciphers and the attacks that break them."""
__version__ = "1.0.0"

from .analysis import (break_caesar, break_caesar_with_known_plaintext,
                       break_substitution, break_vigenere, bigram_score,
                       chi_squared,
                       english_score, frequency, frequency_chart,
                       guess_key_lengths, index_of_coincidence, kasiski_spacings)
from .ciphers import (CIPHERS, CipherError, atbash, caesar, caesar_decrypt,
                      rail_fence, substitution_decrypt, substitution_encrypt,
                      vigenere, xor)

__all__ = [
    "__version__", "caesar", "caesar_decrypt", "atbash", "vigenere",
    "rail_fence", "substitution_encrypt", "substitution_decrypt", "xor",
    "CipherError", "CIPHERS", "frequency", "frequency_chart",
    "index_of_coincidence", "chi_squared", "english_score", "kasiski_spacings",
    "bigram_score", "guess_key_lengths", "break_caesar",
    "break_caesar_with_known_plaintext",
    "break_vigenere", "break_substitution",
]
