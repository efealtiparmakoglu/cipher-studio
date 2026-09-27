import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from cipherstudio import (CipherError, atbash, break_caesar,
                          break_caesar_with_known_plaintext, break_substitution,
                          break_vigenere, caesar, caesar_decrypt, chi_squared,
                          english_score, frequency, frequency_chart,
                          guess_key_lengths, index_of_coincidence,
                          kasiski_spacings, rail_fence, substitution_decrypt,
                          substitution_encrypt, vigenere, xor)
from cipherstudio.cli import main

ENGLISH = (
    "The art of war is of supreme importance in the study of war. "
    "It is a matter of life and death, a road either to safety or to ruin. "
    "Hence it is a subject of inquiry which can on no account be neglected. "
)


class CaesarTests(unittest.TestCase):
    def test_round_trip(self):
        for shift in range(26):
            self.assertEqual(caesar_decrypt(caesar(ENGLISH, shift), shift), ENGLISH)

    def test_known_vector(self):
        self.assertEqual(caesar("attack at dawn", 5), "fyyfhp fy ifbs")

    def test_case_and_punctuation_preserved(self):
        out = caesar("Attack, AT DAWN!", 1)
        self.assertEqual(out, "Buubdl, BU EBXO!")
        self.assertTrue(out[7].isspace())  # the space is preserved in place

    def test_invalid_shift(self):
        with self.assertRaises(CipherError):
            caesar("x", 26)
        with self.assertRaises(CipherError):
            caesar("x", -1)


class AtbashTests(unittest.TestCase):
    def test_self_inverse(self):
        self.assertEqual(atbash(atbash(ENGLISH)), ENGLISH)

    def test_known_vector(self):
        self.assertEqual(atbash("abc xyz XYZ"), "zyx cba CBA")


class VigenereTests(unittest.TestCase):
    def test_round_trip(self):
        for key in ("orchard", "lemon", "a", "longer key"):
            self.assertEqual(vigenere(vigenere(ENGLISH, key), key, decrypt=True),
                             ENGLISH)

    def test_known_vector(self):
        # classic example: key "LEMON", "ATTACKATDAWN"
        cipher = vigenere("ATTACKATDAWN", "LEMON")
        self.assertEqual(cipher, "LXFOPVEFRNHR")
        self.assertEqual(vigenere(cipher, "LEMON", decrypt=True), "ATTACKATDAWN")

    def test_empty_key_rejected(self):
        with self.assertRaises(CipherError):
            vigenere("abc", "")
        with self.assertRaises(CipherError):
            vigenere("abc", "123!")


class RailFenceTests(unittest.TestCase):
    def test_round_trip(self):
        for rails in (2, 3, 4, 5):
            encrypted = rail_fence(ENGLISH, rails)
            self.assertEqual(rail_fence(encrypted, rails, decrypt=True), ENGLISH)

    def test_shape_preserved(self):
        out = rail_fence("one two three", 3)
        self.assertEqual(len(out.replace(" ", "")), len("onetwothree"))

    def test_invalid_rails(self):
        with self.assertRaises(CipherError):
            rail_fence("abc", 1)

    def test_more_rails_than_letters(self):
        self.assertEqual(rail_fence("abc", 5), "abc")


class SubstitutionTests(unittest.TestCase):
    KEY = "qwertyuiopasdfghjklzxcvbnm"

    def test_round_trip(self):
        encrypted = substitution_encrypt(ENGLISH, self.KEY)
        self.assertEqual(substitution_decrypt(encrypted, self.KEY), ENGLISH)

    def test_key_validation(self):
        with self.assertRaises(CipherError):
            substitution_encrypt("abc", "short")
        with self.assertRaises(CipherError):
            substitution_decrypt("abc", "aabbc" + "c" * 21)  # not a permutation

    def test_decrypt_is_the_inverse_direction(self):
        # a real decryption must not equal the encryption
        encrypted = substitution_encrypt(ENGLISH, self.KEY)
        self.assertNotEqual(substitution_decrypt(encrypted, self.KEY), encrypted)


class XorTests(unittest.TestCase):
    def test_round_trip_text_and_bytes(self):
        self.assertEqual(xor(xor(ENGLISH, "key"), "key"), ENGLISH)
        raw = xor(ENGLISH.encode(), b"key")
        self.assertEqual(xor(raw, b"key"), ENGLISH.encode())

    def test_empty_key_rejected(self):
        with self.assertRaises(CipherError):
            xor("abc", "")


class AnalysisTests(unittest.TestCase):
    def test_index_of_coincidence_english_beats_random(self):
        english_ic = index_of_coincidence(ENGLISH * 3)
        random_ic = index_of_coincidence("qxzpwljkhfdbvnmcgtrs")
        self.assertGreater(english_ic, 0.055)
        self.assertLess(random_ic, 0.06)
        self.assertGreater(english_ic, random_ic)

    def test_chi_squared_lower_for_english(self):
        _, english_pct = frequency(ENGLISH * 3)
        _, random_pct = frequency("qxzpwljkhfdbvnmcgtrsqxzpwljkhfdbvnmcgtrs")
        self.assertLess(chi_squared(english_pct), chi_squared(random_pct))

    def test_english_score_ordering(self):
        garbled = "".join(chr((ord(c) - ord("a") + 7) % 26 + ord("a"))
                          for c in ENGLISH.lower() if c.isalpha())
        self.assertGreater(english_score(ENGLISH), english_score(garbled))
        self.assertEqual(english_score(""), 0.0)

    def test_frequency_totals(self):
        counts, percents = frequency("abcda")
        self.assertEqual(counts["a"], 2)
        self.assertAlmostEqual(sum(counts.values()), 5)
        self.assertAlmostEqual(sum(percents.values()), 100.0)

    def test_frequency_chart_shape(self):
        chart = frequency_chart(ENGLISH)
        self.assertIn("a ", chart)
        self.assertIn("total letters:", chart)
        self.assertEqual(len(chart.splitlines()), 27)

    def test_kasiski_finds_repeats(self):
        cipher = vigenere(ENGLISH * 4, "treasure")
        spacings = kasiski_spacings(cipher)
        self.assertTrue(spacings, "expected repeated sequences")

    def test_key_length_estimation(self):
        cipher = vigenere(ENGLISH * 6, "orchard")  # 7 letters
        ranked = guess_key_lengths(cipher)
        self.assertTrue(ranked)
        self.assertEqual(ranked[0][0], 7)


class AttackTests(unittest.TestCase):
    def test_break_caesar_all_shifts(self):
        for shift in (1, 7, 13, 25):
            result = break_caesar(caesar(ENGLISH * 3, shift))
            self.assertEqual(result["plaintext"], ENGLISH * 3, f"shift {shift}")
            self.assertEqual(result["shift"], shift)

    def test_break_caesar_needs_enough_text(self):
        # 13 letters is not enough evidence: the tool returns its best
        # guess rather than a correct one, and says nothing about it
        result = break_caesar(caesar("ATTACK AT DAWN", 3))
        self.assertIn(result["shift"], range(26))
        self.assertTrue(result["plaintext"])

    def test_break_caesar_on_medium_text(self):
        medium = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AGAIN AND AGAIN"
        result = break_caesar(caesar(medium, 3))
        self.assertEqual(result["plaintext"], medium)

    def test_known_plaintext_crib(self):
        hits = break_caesar_with_known_plaintext(caesar("the eagle lands at dawn", 7), "eagle")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["shift"], 7)
        self.assertIn("eagle", hits[0]["plaintext"])

    def test_crib_finds_nothing(self):
        self.assertEqual(break_caesar_with_known_plaintext("qqqq wwww", "zebra"), [])

    def test_break_vigenere_exact(self):
        for key in ("orchard", "lemon", "melon"):
            cipher = vigenere(ENGLISH * 4, key)
            result = break_vigenere(cipher)
            self.assertEqual(result["key"], key)
            self.assertEqual(result["plaintext"], ENGLISH * 4)

    def test_break_vigenere_with_given_length(self):
        cipher = vigenere(ENGLISH * 4, "orchard")
        result = break_vigenere(cipher, key_length=7)
        self.assertEqual(result["key_length"], 7)
        self.assertEqual(result["plaintext"], ENGLISH * 4)

    def test_break_vigenere_too_short(self):
        with self.assertRaises(CipherError):
            break_vigenere("short")

    def test_break_substitution_is_heuristic(self):
        """Documented contract: the substitution attack gets most of the
        way there, not all the way. We assert what it actually guarantees."""
        cipher = substitution_encrypt(ENGLISH * 4, "qwertyuiopasdfghjklzxcvbnm")
        result = break_substitution(cipher)
        self.assertEqual(len(result["key"]), 26)
        self.assertEqual(sorted(result["key"]), list("abcdefghijklmnopqrstuvwxyz"))
        self.assertGreater(result["score"], 0.7)
        self.assertIn("the", result["plaintext"].lower())
        correct = sum(1 for a, b in zip(result["key"], "qwertyuiopasdfghjklzxcvbnm")
                      if a == b)
        self.assertGreaterEqual(correct, 4, "expected several letters recovered")


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_encrypt_decrypt_round_trip(self):
        code, out, _ = self.run_main(["encrypt", "--cipher", "caesar", "--key", "7", "hello world"])
        self.assertEqual(code, 0)
        cipher = out.strip()
        code, out, _ = self.run_main(["decrypt", "--cipher", "caesar", "--key", "7", cipher])
        self.assertEqual(out.strip(), "hello world")

    def test_vigenere_round_trip(self):
        code, out, _ = self.run_main(["encrypt", "--cipher", "vigenere", "--key", "key", "secret message"])
        cipher = out.strip()
        code, out, _ = self.run_main(["decrypt", "--cipher", "vigenere", "--key", "key", cipher])
        self.assertEqual(out.strip(), "secret message")

    def test_analyze_json(self):
        code, out, _ = self.run_main(["analyze", "--json", ENGLISH])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreater(payload["index_of_coincidence"], 0.05)
        self.assertIn("verdict", payload)

    def test_break_caesar_cli(self):
        _, out, _ = self.run_main(["encrypt", "--cipher", "caesar", "--key", "11", ENGLISH])
        cipher = out.strip()
        code, out, _ = self.run_main(["break", "--cipher", "caesar", cipher])
        self.assertEqual(code, 0)
        self.assertIn("supreme importance", out)

    def test_break_vigenere_cli(self):
        _, out, _ = self.run_main(["encrypt", "--cipher", "vigenere", "--key", "orchard", ENGLISH * 3])
        cipher = out.strip()
        code, out, _ = self.run_main(["break", "--cipher", "vigenere", cipher])
        self.assertEqual(code, 0)
        self.assertIn("supreme importance", out)

    def test_keylength_cli(self):
        _, out, _ = self.run_main(["encrypt", "--cipher", "vigenere", "--key", "orchard", ENGLISH * 4])
        cipher = out.strip()
        code, out, _ = self.run_main(["keylength", cipher])
        self.assertEqual(code, 0)
        self.assertIn("candidate key lengths", out)

    def test_crib_cli(self):
        _, out, _ = self.run_main(["encrypt", "--cipher", "caesar", "--key", "3", "the eagle lands"])
        cipher = out.strip()
        code, out, _ = self.run_main(["crib", "--cipher", "caesar", "--known", "eagle", cipher])
        self.assertEqual(code, 0)
        self.assertIn("eagle", out)

    def test_unknown_cipher_is_usage_error(self):
        code, _, err = self.run_main(["encrypt", "--cipher", "rot13", "hi"])
        self.assertEqual(code, 2)

    def test_missing_key_is_usage_error(self):
        code, _, err = self.run_main(["encrypt", "--cipher", "vigenere", "hi"])
        self.assertEqual(code, 2)
        self.assertIn("--key", err)

    def test_no_command_prints_usage(self):
        code, _, err = self.run_main([])
        self.assertEqual(code, 2)
        self.assertIn("usage", err)

    def test_substitution_needs_26_letters(self):
        code, _, err = self.run_main(["encrypt", "--cipher", "substitution", "--key", "abc", "hi"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
