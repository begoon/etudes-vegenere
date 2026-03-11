#!/usr/bin/env python3
"""
Program 2: Decrypt a modified Vigenère cipher using a known keyword.

Reads the keyword and mixed alphabet from cipher-params.txt
(produced by find_keyword.py), then decrypts crypted-ru.txt.

Encryption: C = MIXED[(STD.index(P) + STD.index(K)) % 32]
Decryption: P = STD[(MIXED.index(C) - STD.index(K)) % 32]
"""

ALPHA = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
N = 32
STD_IDX = {c: i for i, c in enumerate(ALPHA)}


def read_params(fn="cipher-params.txt"):
    """Read keyword and alphabet from parameters file."""
    params = {}
    with open(fn, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                params[key] = val
    return params["keyword"], params["alphabet"]


def read_ct(fn="crypted-ru.txt"):
    """Read and clean ciphertext."""
    with open(fn, "r", encoding="utf-8") as f:
        text = f.read()
    return "".join(c for c in text.upper() if c in ALPHA)


def decrypt(ct, keyword, mixed_alphabet):
    """Decrypt ciphertext using keyword and mixed alphabet."""
    mixed_inv = {c: i for i, c in enumerate(mixed_alphabet)}
    shifts = [STD_IDX[k] for k in keyword]
    L = len(keyword)

    pt = []
    for i, c in enumerate(ct):
        m_idx = mixed_inv[c]
        p_std = (m_idx - shifts[i % L]) % N
        pt.append(ALPHA[p_std])
    return "".join(pt)


def format_text(text, width=55):
    """Format text into lines of given width."""
    lines = []
    for i in range(0, len(text), width):
        lines.append(text[i : i + width])
    return "\n".join(lines)


def main():
    keyword, mixed_alphabet = read_params()
    ct = read_ct()

    print(f"Keyword:  {keyword}")
    print(f"Alphabet: {mixed_alphabet}")
    print(f"Ciphertext length: {len(ct)} chars\n")

    pt = decrypt(ct, keyword, mixed_alphabet)

    print("=== Decrypted text ===\n")
    print(format_text(pt))
    print()


if __name__ == "__main__":
    main()
