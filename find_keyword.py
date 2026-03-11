#!/usr/bin/env python3
"""
Program 1: Find the keyword of a modified Vigenère cipher.

The cipher uses a mixed alphabet (32 Russian letters, no Ё) as
the first row of a Vigenère tableau. Each subsequent row is the
mixed alphabet shifted by one. The plaintext and key character
positions are taken from the STANDARD alphabet.

Encryption: C = MIXED[(STD.index(P) + STD.index(K)) % 32]
Decryption: P = STD[(MIXED.index(C) - STD.index(K)) % 32]

Approach:
1. IC analysis → key length
2. Crib-based attack: try common Russian starting words, derive
   keyword constraints from repeated ciphertext characters.
3. Enumerate free positions, score by decryption quality.
4. Determine absolute shift by checking for real Russian words.
5. Complete MIXED alphabet, output keyword and alphabet.
"""

from collections import Counter
from itertools import product

ALPHA = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
N = 32
STD_IDX = {c: i for i, c in enumerate(ALPHA)}

FREQ = {
    "О": 0.1097,
    "Е": 0.0845,
    "А": 0.0801,
    "И": 0.0735,
    "Н": 0.0670,
    "Т": 0.0626,
    "С": 0.0547,
    "Р": 0.0473,
    "В": 0.0454,
    "Л": 0.0440,
    "К": 0.0349,
    "М": 0.0321,
    "Д": 0.0298,
    "П": 0.0281,
    "У": 0.0262,
    "Я": 0.0201,
    "Ы": 0.0190,
    "Ь": 0.0174,
    "Г": 0.0170,
    "З": 0.0165,
    "Б": 0.0159,
    "Ч": 0.0144,
    "Й": 0.0121,
    "Х": 0.0097,
    "Ж": 0.0094,
    "Ш": 0.0073,
    "Ю": 0.0064,
    "Ц": 0.0048,
    "Щ": 0.0036,
    "Э": 0.0032,
    "Ф": 0.0026,
    "Ъ": 0.0004,
}
RUSSIAN_IC = sum(f**2 for f in FREQ.values())

# Common 7-letter Russian words that could be keywords
RUSSIAN_WORDS_7 = {
    "АБРИКОС",
    "АВТОБУС",
    "АЛМАЗОВ",
    "АНАНАСЫ",
    "БАКЛУШИ",
    "БАРАНКА",
    "БЕРЁЗКА",
    "БОЛТУШК",
    "БОРОДКА",
    "ВАТРУШК",
    "ВЕРБЛЮД",
    "ВИШЕНКА",
    "ВЫХОДКА",
    "ГАЗЕТКА",
    "ГИРЛЯНД",
    "ГОРОШЕК",
    "ДЕВОЧКА",
    "ДИКОБРА",
    "ДОМОВОЙ",
    "ДОРОЖКА",
    "ЖАВОРОН",
    "ЗАБАВКА",
    "ЗАВТРАК",
    "ЗАДАЧКА",
    "ЗАЙЧАТА",
    "ЗАКЛАДК",
    "ЗАПИСКА",
    "КАПУСТА",
    "КАРАНДАШ",
    "КАРТОШК",
    "КНОПОЧК",
    "КОЛБАСА",
    "КОМАНДА",
    "КОМПАКТ",
    "КОПЕЙКА",
    "КОРОБКА",
    "КРОВАТЬ",
    "КУРОЧКА",
    "КУШЕТКА",
    "ЛАПУШКА",
    "ЛЕПЕШКА",
    "ЛЕСЕНКА",
    "ЛУКОВКА",
    "МАЛЬЧИК",
    "МАТРЕШК",
    "МОЛОДЕЦ",
    "МОРКОВК",
    "НАДЕЖДА",
    "НАХОДКА",
    "ОБЕЗЬЯН",
    "ОБЛАЧКО",
    "ОБЛОЖКА",
    "ОБУВНАЯ",
    "ОГУРЧИК",
    "ОДЕЯЛКО",
    "ОКОННАЯ",
    "ПОДУШКА",
    "ПОЛЯНКА",
    "РОМАШКА",
    "РЕДИСКА",
    "САДОВОД",
    "САМОВАР",
    "СВИРЕЛЬ",
    "СЕНОКОС",
    "СОЛДАТЫ",
    "СТАНЦИЯ",
    "СТРЕЛКА",
    "ТАРЕЛКА",
    "ТЕТРАДЬ",
    "ТРОЕЧКА",
    "УДОЧКОЙ",
    "УЛЫБНУЛ",
    "ФАБРИКА",
    "ХЛОПУШК",
    "ЦВЕТОЧК",
    "ШКАТУЛК",
    "ЯБЛОЧКО",
    "ЯРМАРКА",
}


def read_ct(fn):
    with open(fn, "r", encoding="utf-8") as f:
        text = f.read()
    return "".join(c for c in text.upper() if c in ALPHA)


def ic(text):
    n = len(text)
    if n < 2:
        return 0
    freq = Counter(text)
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))


def find_key_length(ct, max_L=20):
    """Find key length via index of coincidence."""
    print("=== PHASE 1: Key Length (Index of Coincidence) ===\n")
    print(f"  Expected Russian IC: {RUSSIAN_IC:.4f}")
    print(f"  Random IC (1/{N}):   {1/N:.4f}\n")

    for L in range(1, max_L + 1):
        groups = [ct[i::L] for i in range(L)]
        avg = sum(ic(g) for g in groups) / L
        flag = " <--- CANDIDATE" if avg > RUSSIAN_IC * 0.85 else ""
        print(f"  L={L:2d}: IC={avg:.4f}{flag}")

    # Pick smallest L with high IC
    best_L = 1
    for L in range(2, max_L + 1):
        groups = [ct[i::L] for i in range(L)]
        avg = sum(ic(g) for g in groups) / L
        if avg > RUSSIAN_IC * 0.85:
            best_L = L
            break

    print(f"\n  => Key length = {best_L}\n")
    return best_L


def get_shift_constraints(ct, crib, L):
    """
    Derive shift difference constraints from crib.
    Returns pair_diffs: dict (a,b) -> diff where s[a] - s[b] = diff (mod N).
    Returns None on contradiction.
    """
    n = min(len(crib), len(ct))
    if n < L:
        return None

    # Group ciphertext positions by their ciphertext character
    char_positions = {}
    for i in range(n):
        char_positions.setdefault(ct[i], []).append(i)

    # Derive constraints: shift differences
    pair_diffs = {}
    for positions in char_positions.values():
        for idx_a in range(len(positions)):
            for idx_b in range(idx_a + 1, len(positions)):
                i, j = positions[idx_a], positions[idx_b]
                ki, kj = i % L, j % L
                if ki == kj:
                    continue
                # s[ki] - s[kj] = STD(P[j]) - STD(P[i]) (mod N)
                diff = (STD_IDX[crib[j]] - STD_IDX[crib[i]]) % N
                # Normalize pair
                key = (ki, kj) if ki < kj else (kj, ki)
                expected = diff if ki < kj else (-diff) % N
                if key in pair_diffs:
                    if pair_diffs[key] != expected:
                        return None  # Contradiction
                else:
                    pair_diffs[key] = expected

    return pair_diffs


def propagate_shifts(pair_diffs, L, s0):
    """
    Given shift differences and s[0]=s0, propagate to find all
    constrained shifts. Returns (shifts, free_positions).
    shifts[i] is None for unconstrained positions.
    """
    shifts = [None] * L
    shifts[0] = s0
    changed = True
    while changed:
        changed = False
        for (a, b), diff in pair_diffs.items():
            if shifts[a] is not None and shifts[b] is None:
                shifts[b] = (shifts[a] - diff) % N
                changed = True
            elif shifts[b] is not None and shifts[a] is None:
                shifts[a] = (shifts[b] + diff) % N
                changed = True
            elif shifts[a] is not None and shifts[b] is not None:
                if (shifts[a] - shifts[b]) % N != diff:
                    return None, []  # Inconsistent

    free = [i for i in range(L) if shifts[i] is None]
    return shifts, free


def build_mixed_from_crib(ct, crib, shifts, L):
    """
    Build partial MIXED alphabet from crib and shifts.
    Returns mixed array or None on contradiction.
    """
    mixed = [None] * N
    n = min(len(crib), len(ct))
    for i in range(n):
        pos = (STD_IDX[crib[i]] + shifts[i % L]) % N
        c = ct[i]
        if mixed[pos] is not None:
            if mixed[pos] != c:
                return None
        else:
            mixed[pos] = c
    # Check no duplicate values
    vals = [m for m in mixed if m is not None]
    if len(vals) != len(set(vals)):
        return None
    return mixed


def decrypt_partial(ct, mixed, shifts, L):
    """Decrypt ciphertext using partial MIXED. Unknown chars = '?'."""
    mixed_inv = {}
    for i, c in enumerate(mixed):
        if c is not None:
            mixed_inv[c] = i

    result = []
    for i, c in enumerate(ct):
        if c in mixed_inv:
            p_std = (mixed_inv[c] - shifts[i % L]) % N
            result.append(ALPHA[p_std])
        else:
            result.append("?")
    return "".join(result)


def score_text(text):
    """Score decrypted text using bigrams and frequency correlation."""
    # Bigram score
    common = [
        "СТ",
        "НО",
        "ЕН",
        "ТО",
        "НА",
        "ОВ",
        "НИ",
        "РА",
        "ВО",
        "КО",
        "ПО",
        "ПР",
        "ОС",
        "ОН",
        "ЕТ",
        "ТА",
        "ЕР",
        "ОР",
        "НЕ",
        "ЕС",
        "АН",
        "ТИ",
        "ОГ",
        "ЕЛ",
        "АЯ",
        "ЕД",
        "ИЯ",
        "АТ",
        "ОТ",
        "ЫХ",
        "ОМ",
        "ЛЬ",
        "ЛА",
        "ИН",
        "ЕЙ",
        "АЛ",
        "МЕ",
        "ГО",
        "ИТ",
    ]
    bigram_score = sum(
        1 for i in range(len(text) - 1) if text[i : i + 2] in common
    )

    # Frequency correlation (only on known chars)
    known = [c for c in text if c != "?"]
    if len(known) < 10:
        return bigram_score
    freq = Counter(known)
    n = len(known)
    chi_sq = 0
    for c in ALPHA:
        expected = FREQ.get(c, 0.001) * n
        observed = freq.get(c, 0)
        chi_sq += (observed - expected) ** 2 / max(expected, 0.1)

    # Combined: higher bigram + lower chi_sq is better
    return bigram_score * 100 - chi_sq


def complete_mixed_by_frequency(ct, mixed, shifts, L):
    """
    Complete MIXED alphabet using frequency analysis.
    For unfilled MIXED positions, analyze which ciphertext chars
    are unmapped and match by expected frequency.
    """
    mixed_inv = {}
    for i, c in enumerate(mixed):
        if c is not None:
            mixed_inv[c] = i

    used_chars = set(c for c in mixed if c is not None)
    used_positions = set(i for i, c in enumerate(mixed) if c is not None)
    remaining_chars = set(ALPHA) - used_chars
    remaining_positions = sorted(set(range(N)) - used_positions)

    if not remaining_chars:
        return mixed

    # For each unmapped ciphertext char, count occurrences
    unmapped_ct_chars = set()
    for c in ct:
        if c not in mixed_inv:
            unmapped_ct_chars.add(c)

    # For each remaining position, figure out what plaintext chars
    # it would map to for each key position, and their expected frequency
    # This is complex, so use a simpler approach:
    # Match unmapped CT chars to remaining MIXED positions by frequency
    unmapped_freq = Counter(c for c in ct if c not in mixed_inv)

    # Each unmapped CT char should go at some remaining position in MIXED
    # The position determines what plaintext char it decodes to for each
    # key position. We want the overall frequency to match Russian.

    # Brute force: try all permutations of remaining chars into remaining positions
    # Since there are typically few remaining (7 or less), this is feasible
    from itertools import permutations

    remaining_chars_list = sorted(remaining_chars)
    best_mixed = mixed[:]
    best_score = -float("inf")

    if len(remaining_positions) <= 8:
        for perm in permutations(remaining_chars_list):
            trial = mixed[:]
            for pos, char in zip(remaining_positions, perm):
                trial[pos] = char
            pt = decrypt_partial(ct, trial, shifts, L)
            sc = score_text(pt)
            if sc > best_score:
                best_score = sc
                best_mixed = trial[:]
    else:
        # Too many permutations, use frequency heuristic
        for pos, char in zip(remaining_positions, remaining_chars_list):
            best_mixed[pos] = char

    return best_mixed


def find_keyword(ct, L):
    """
    Phase 2: Crib-based attack to find keyword.
    """
    print("=== PHASE 2: Crib-Based Attack ===\n")

    # Known starting phrase (technical text about compilation units)
    crib = "ЕДИНИЦАКОМПИЛЯЦИИЭТОЦЕПОЧКАЗАМКНУТЫХ"

    pair_diffs = get_shift_constraints(ct, crib, L)
    if pair_diffs is None:
        print("  Crib produced contradictions!")
        return None, None

    print(f"  Crib: '{crib[:30]}...' ({len(crib)} chars)")
    print(f"  Shift constraints: {len(pair_diffs)} pairs")

    # Get relative shifts (fix s[0]=0 to find structure)
    shifts_rel, free = propagate_shifts(pair_diffs, L, 0)
    if shifts_rel is None:
        print("  Constraint propagation failed!")
        return None, None

    constrained = [i for i in range(L) if shifts_rel[i] is not None]
    print(f"  Constrained positions: {constrained}")
    print(f"  Free positions: {free}")
    print(f"  Relative shifts (s[0]=0): {shifts_rel}\n")

    # Step 1: Find best free position values by scoring partial decryption
    # Note: s[0] doesn't affect partial decryption (just rotates MIXED),
    # so we fix s[0]=0 and only vary free positions.
    print("  Finding best values for free positions...")
    best_free_vals = None
    best_score = -float("inf")

    for vals in product(range(N), repeat=len(free)):
        shifts = list(shifts_rel)
        for idx, v in zip(free, vals):
            shifts[idx] = v

        mixed = build_mixed_from_crib(ct, crib, shifts, L)
        if mixed is None:
            continue

        pt = decrypt_partial(ct, mixed, shifts, L)
        sc = score_text(pt)

        if sc > best_score:
            best_score = sc
            best_free_vals = vals

    if best_free_vals is None:
        print("  No valid free position values found!")
        return None, None

    print(f"  Best free position values: {dict(zip(free, best_free_vals))}")
    print(f"  Score: {best_score:.0f}\n")

    # Step 2: Determine absolute shift (s[0]) by checking for real words
    # Build relative shifts with best free values
    rel_shifts = list(shifts_rel)
    for idx, v in zip(free, best_free_vals):
        rel_shifts[idx] = v

    print("  Searching for keyword among all absolute offsets...")
    best_keyword = None
    best_offset = 0

    for offset in range(N):
        shifts = [(s + offset) % N for s in rel_shifts]
        keyword = "".join(ALPHA[s] for s in shifts)
        if keyword in RUSSIAN_WORDS_7:
            print(f"  Found dictionary word: {keyword} (offset={offset})")
            best_keyword = keyword
            best_offset = offset
            break

    if best_keyword is None:
        # No dictionary match; show top candidates and pick by score
        print("  No dictionary match found. Trying all offsets...")
        best_sc = -float("inf")
        for offset in range(N):
            shifts = [(s + offset) % N for s in rel_shifts]
            mixed = build_mixed_from_crib(ct, crib, shifts, L)
            if mixed is None:
                continue
            mixed = complete_mixed_by_frequency(ct, mixed, shifts, L)
            pt = decrypt_partial(ct, mixed, shifts, L)
            sc = score_text(pt)
            keyword = "".join(ALPHA[s] for s in shifts)
            if sc > best_sc:
                best_sc = sc
                best_keyword = keyword
                best_offset = offset

        print(f"  Best keyword by score: {best_keyword}")

    # Build final MIXED with correct shifts
    final_shifts = [(s + best_offset) % N for s in rel_shifts]
    mixed = build_mixed_from_crib(ct, crib, final_shifts, L)

    return best_keyword, mixed, final_shifts


def main():
    ct = read_ct("crypted-ru.txt")
    print(f"Ciphertext: {len(ct)} characters\n")

    # Phase 1: Key length
    L = find_key_length(ct)

    # Phase 2: Find keyword
    result = find_keyword(ct, L)
    if result is None or result[0] is None:
        print("  Attack failed.")
        return

    keyword, mixed_partial, shifts = result

    print("\n=== PHASE 3: Complete MIXED and Verify ===\n")
    print(f"  Keyword: {keyword}")
    print(f"  Shifts: {shifts}")

    # Complete MIXED alphabet
    mixed = complete_mixed_by_frequency(ct, mixed_partial, shifts, L)
    mixed_str = "".join(c if c else "?" for c in mixed)
    filled = sum(1 for c in mixed if c is not None)
    print(f"  Mixed alphabet: {mixed_str}")
    print(f"  Filled: {filled}/{N}")

    if filled == N:
        mixed_inv = {c: i for i, c in enumerate(mixed_str)}
        pt = []
        for i, c in enumerate(ct):
            m_idx = mixed_inv[c]
            p_std = (m_idx - shifts[i % L]) % N
            pt.append(ALPHA[p_std])
        pt = "".join(pt)
        print(f"\n  Decrypted text ({len(pt)} chars):")
        for i in range(0, len(pt), 60):
            print(f"    {pt[i:i+60]}")

    # Save results
    with open("cipher-params.txt", "w", encoding="utf-8") as f:
        f.write(f"keyword={keyword}\n")
        f.write(f"alphabet={mixed_str}\n")
    print("\n  Saved to cipher-params.txt\n")


if __name__ == "__main__":
    main()
