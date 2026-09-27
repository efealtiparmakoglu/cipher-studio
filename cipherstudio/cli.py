"""cipher-studio CLI: encrypt, analyze, break."""
import argparse
import json
import sys

from . import __version__
from .analysis import (break_caesar, break_caesar_with_known_plaintext,
                       break_substitution, break_vigenere, english_score,
                       frequency_chart, guess_key_lengths, index_of_coincidence,
                       kasiski_spacings)
from .ciphers import (CIPHERS, CipherError, atbash, caesar, caesar_decrypt,
                      rail_fence, substitution_decrypt, substitution_encrypt,
                      vigenere, xor)

USAGE = f"""cipher-studio {__version__} — classical cipher workbench (educational)

ciphers: {', '.join(f'{name} ({note})' for name, note in CIPHERS.items())}

usage:
  cipher-studio encrypt --cipher caesar --key 3 "text here"
  cipher-studio decrypt --cipher vigenere --key secret "cipher here"
  cipher-studio analyze "text"                 frequency chart + IC
  cipher-studio break --cipher caesar "text"   crack it
  cipher-studio break --cipher vigenere "text" [--key-length N]
  cipher-studio break --cipher substitution "text"
  cipher-studio crib --cipher caesar --known the "text"
  cipher-studio keylength "vigenere ciphertext"  Kasiski + per-stream IC

options:
  --json    machine-readable output
  -h        this text

exit codes: 0 ok, 1 analysis failed, 2 usage error
"""


def _cipher_action(args, decrypt=False):
    text = "".join(args.text)
    if not text:
        print("cipher-studio: no text given", file=sys.stderr)
        return 2
    name = args.cipher
    try:
        if name == "caesar":
            shift = int(args.key or 0)
            result = caesar_decrypt(text, shift) if decrypt else caesar(text, shift)
        elif name == "atbash":
            result = atbash(text)
        elif name == "vigenere":
            if not args.key:
                print("cipher-studio: vigenere needs --key", file=sys.stderr)
                return 2
            result = vigenere(text, args.key, decrypt=decrypt)
        elif name == "railfence":
            rails = int(args.key or 3)
            result = rail_fence(text, rails, decrypt=decrypt)
        elif name == "substitution":
            if not args.key or len(args.key) != 26:
                print("cipher-studio: substitution needs a 26-letter --key",
                      file=sys.stderr)
                return 2
            result = (substitution_decrypt(text, args.key) if decrypt
                      else substitution_encrypt(text, args.key))
        elif name == "xor":
            if not args.key:
                print("cipher-studio: xor needs --key", file=sys.stderr)
                return 2
            result = xor(text, args.key)
        else:
            print(f"cipher-studio: unknown cipher '{name}'", file=sys.stderr)
            return 2
    except (CipherError, ValueError) as exc:
        print(f"cipher-studio: {exc}", file=sys.stderr)
        return 2
    print(result)
    return 0


def _cmd_analyze(args):
    text = "".join(args.text)
    ic = index_of_coincidence(text)
    score = english_score(text)
    if args.json:
        print(json.dumps({
            "index_of_coincidence": round(ic, 5),
            "english_score": round(score, 3),
            "verdict": _verdict(ic, score),
        }, indent=2))
        return 0
    print(frequency_chart(text))
    print()
    print(f"index of coincidence: {ic:.5f}  (English ~0.065, random ~0.038)")
    print(f"english score:       {score:.3f}")
    print(f"verdict:             {_verdict(ic, score)}")
    return 0


def _verdict(ic, score):
    if score > 0.7:
        return "looks like plain English"
    if ic > 0.06:
        return "letter distribution looks English-ish (monoalphabetic?)"
    return "flat distribution: possibly polyalphabetic (Vigenere) or random"


def _cmd_break(args):
    text = "".join(args.text)
    if not text:
        print("cipher-studio: no text given", file=sys.stderr)
        return 2
    try:
        if args.cipher == "caesar":
            result = break_caesar(text)
        elif args.cipher == "vigenere":
            result = break_vigenere(text, args.key_length)
        elif args.cipher == "substitution":
            result = break_substitution(text)
        else:
            print(f"cipher-studio: cannot break '{args.cipher}' automatically",
                  file=sys.stderr)
            return 2
    except CipherError as exc:
        print(f"cipher-studio: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({k: v for k, v in result.items()}, indent=2, default=str))
        return 0
    print(result["plaintext"])
    details = [f"{k}={v}" for k, v in result.items() if k != "plaintext"]
    print(f"  ({', '.join(details)})", file=sys.stderr)
    return 0


def _cmd_crib(args):
    text = "".join(args.text)
    if args.cipher != "caesar":
        print("cipher-studio: crib dragging is implemented for caesar",
              file=sys.stderr)
        return 2
    results = break_caesar_with_known_plaintext(text, args.known or "the")
    if not results:
        print("no shift produces the crib", file=sys.stderr)
        return 1
    for hit in results:
        print(f"shift {hit['shift']}: {hit['plaintext']}")
    return 0


def _cmd_keylength(args):
    text = "".join(args.text)
    ranked = guess_key_lengths(text)
    if not ranked:
        print("cipher-studio: ciphertext too short", file=sys.stderr)
        return 1
    spacings = kasiski_spacings(text)
    if args.json:
        print(json.dumps({
            "kasiski_spacings": spacings[:40],
            "candidates": [{"length": length, "ic": round(ic, 5)}
                           for length, ic in ranked[:8]],
        }, indent=2))
        return 0
    print("Kasiski spacings:", spacings[:20] or "(no repeats found)")
    print("candidate key lengths by per-stream index of coincidence:")
    for length, ic in ranked[:8]:
        print(f"  length {length:2d}: IC {ic:.5f}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="cipher-studio", add_help=False,
                                     description="classical cipher workbench")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="version", version=f"cipher-studio {__version__}")
    sub = parser.add_subparsers(dest="command")

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name)
        p.add_argument("--cipher", required=True, choices=sorted(CIPHERS))
        p.add_argument("--key", default="")
        p.add_argument("text", nargs="+")

    p_analyze = sub.add_parser("analyze")
    p_analyze.add_argument("--json", action="store_true")
    p_analyze.add_argument("text", nargs="+")

    p_break = sub.add_parser("break")
    p_break.add_argument("--cipher", required=True,
                         choices=["caesar", "vigenere", "substitution"])
    p_break.add_argument("--key-length", type=int, default=None)
    p_break.add_argument("--json", action="store_true")
    p_break.add_argument("text", nargs="+")

    p_crib = sub.add_parser("crib")
    p_crib.add_argument("--cipher", default="caesar")
    p_crib.add_argument("--known", default="the")
    p_crib.add_argument("text", nargs="+")

    p_key = sub.add_parser("keylength")
    p_key.add_argument("--json", action="store_true")
    p_key.add_argument("text", nargs="+")
    return parser


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse errors: bad choice, missing value
        return int(exc.code) if exc.code else 2
    if getattr(args, "help", False) or args.command is None:
        print(USAGE, file=sys.stderr)
        return 2
    if args.command in ("encrypt", "decrypt"):
        return _cipher_action(args, decrypt=args.command == "decrypt")
    if args.command == "analyze":
        return _cmd_analyze(args)
    if args.command == "break":
        return _cmd_break(args)
    if args.command == "crib":
        return _cmd_crib(args)
    if args.command == "keylength":
        return _cmd_keylength(args)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
