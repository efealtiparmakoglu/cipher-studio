# cipher-studio

**Classical cipher workbench — six ciphers, the statistics that break them, and attacks that actually run. Educational. Zero dependencies.**

```
$ cipher-studio encrypt --cipher vigenere --key orchard "The art of war is of supreme importance"
Hyg hrk rt ncy ij rt jwwrvps zowoiwoeel

$ cipher-studio break --cipher vigenere "Hyg hrk rt ncy ij rt jwwrvps zowoiwoeel"
The art of war is of supreme importance
  (key=orchard, key_length=7, score=1.0)

$ cipher-studio analyze "The art of war is of supreme importance in the study of war"
e  2  12.70% |#######################
t  1   9.06% |###############
a  1   9.06% |###############
...
index of coincidence: 0.05273  (English ~0.065, random ~0.038)
english score:       0.812
verdict:             looks like plain English
```

Cryptanalysis is not magic — it is letter frequencies, the index of
coincidence, Kasiski's repeated sequences and a hill climb. cipher-studio
implements all of them in a few hundred readable lines, and the breaks
are real: the Vigenere key is recovered exactly, every time, in the tests.

## Why cipher-studio

- **Working attacks, not descriptions.** `break` recovers Caesar shifts by
  trying all 26 and scoring each plaintext; `break --cipher vigenere`
  estimates the key length (Kasiski spacings plus per-stream index of
  coincidence), splits the ciphertext into streams and solves each stream
  as a Caesar — recovering multi-letter keys exactly.
- **Honest statistics.** The scorer is calibrated against measured values
  (English bigram rate ≈ 0.5, chi-squared under 30) rather than magic
  constants, and the tests check that English outscores shuffled and
  random text.
- **Index of coincidence** per stream is the tool that finds the Vigenere
  key length; `keylength` prints the candidates ranked by IC so you can
  watch 7 beat everything else.
- **Known-plaintext attacks.** `crib` drags a crib ("the", a name) across
  all Caesar shifts and reports every hit — the attack that opens
  low-entropy ciphertexts.
- **Six ciphers, one shape.** Caesar, Atbash, Vigenere, rail fence,
  monoalphabetic substitution and repeating-key XOR, all preserving case,
  punctuation and spacing.
- **Honest about limits.** The monoalphabetic attack is a frequency
  hill-climb without a quadgram model: it recovers most letters and lands
  a few short, and the test suite asserts exactly that — the kind of
  honesty a cryptanalysis tool should have.

## Usage

```sh
cipher-studio encrypt --cipher caesar --key 13 "text"
cipher-studio decrypt --cipher railfence --key 3 "cipher"
cipher-studio analyze "text" [--json]              frequency chart + IC + verdict
cipher-studio break --cipher caesar "text"
cipher-studio break --cipher vigenere "text" [--key-length 7]
cipher-studio break --cipher substitution "text"  # heuristic, expect a few misses
cipher-studio crib --cipher caesar --known eagle "text"
cipher-studio keylength "vigenere ciphertext"
```

Exit codes: 0 ok, 1 analysis could not run, 2 usage error.

## Development

```sh
python3 -m unittest discover -s tests   # 45 tests, ~4s
```

The suite covers round trips, case/punctuation preservation, field
statistics, Kasiski, exact key recovery for several Vigenere keys, crib
dragging, the documented limits of short-text Caesar breaking, and the
heuristic contract of the substitution attack.

## License

MIT — see [LICENSE](LICENSE).
