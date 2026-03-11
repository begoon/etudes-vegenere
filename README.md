# etudes-vs

Breaking a modified Vigenere cipher on Russian text.

The cipher uses a 32-character Russian alphabet (without Ё) with a randomly mixed base alphabet instead of the standard one.

```text
Encryption: C = MIXED[(STD.index(P) + STD.index(K)) % 32]
Decryption: P = STD[(MIXED.index(C) - STD.index(K)) % 32]
```

The encrypted text is from C. Wetherell's "Etudes for Programmers" (Russian translation).

## Setup

```sh
uv sync
source .venv/bin/activate
```

## Program 1: Find the keyword

`find_keyword.py` analyzes `crypted-ru.txt` and determines the keyword and mixed alphabet using:

1. Index of Coincidence to find key length
2. Crib-based attack with a known plaintext fragment
3. Dictionary check to resolve the absolute shift ambiguity

```text
$ python find_keyword.py

Ciphertext: 738 characters

=== PHASE 1: Key Length (Index of Coincidence) ===

  Expected Russian IC: 0.0558
  Random IC (1/32):   0.0312

  L= 7: IC=0.0518 <--- CANDIDATE
  ...

  => Key length = 7

=== PHASE 2: Crib-Based Attack ===

  Crib: 'ЕДИНИЦАКОМПИЛЯЦИИЭТОЦЕПОЧКАЗАМ...' (36 chars)
  Shift constraints: 7 pairs
  Constrained positions: [0, 2, 3, 4, 5, 6]
  Free positions: [1]
  Relative shifts (s[0]=0): [0, None, 20, 24, 1, 26, 16]

  Finding best values for free positions...
  Best free position values: {1: 21}
  Score: 13328

  Searching for keyword among all absolute offsets...
  Found dictionary word: РЕДИСКА (offset=16)

=== PHASE 3: Complete MIXED and Verify ===

  Keyword: РЕДИСКА
  Shifts: [16, 5, 4, 8, 17, 10, 0]
  Mixed alphabet: ЕХЭЦРБТИОНЪДФГЩЯВУЗШЬЖКЛМПЫЮСЙЧА

  Saved to cipher-params.txt
```

The result is saved to `cipher-params.txt`:

```text
keyword=РЕДИСКА
alphabet=ЕХЭЦРБТИОНЪДФГЩЯВУЗШЬЖКЛМПЫЮСЙЧА
```

## Program 2: Decrypt the text

`crack.py` reads the keyword and alphabet from `cipher-params.txt` and decrypts `crypted-ru.txt`.

```text
$ python crack.py

Keyword:  РЕДИСКА
Alphabet: ЕХЭЦРБТИОНЪДФГЩЯВУЗШЬЖКЛМПЫЮСЙЧА
Ciphertext length: 738 chars

=== Decrypted text ===

ЕДИНИЦАКОМПИЛЯЦИИЭТОЦЕПОЧКАЗАМКНУТЫХПРОГРАММНЫХСЕГМЕНТО
ВТОЧКАКАЖДЫЙПРОГРАММНЫЙСЕГМЕНТЕСТЬЛИБОГЛАВНАЯПРОГРАММАЛ
ИБОВНЕШНЯЯПРОЦЕДУРАТОЧКАВСЕСЕГМЕНТЫЕДИНИЦЫКОМПИЛЯЦИИСВЯ
ЗЫВАЕТДРУГСДРУГОМЗАГРУЗЧИКОДНАКОНЕОБЯЗАТЕЛЬНОЧТОБЫВСЕСЕ
ГМЕНТЫНУЖНЫЕДЛЯПОЛНОЙЗАГРУЗКИКОМПИЛИРОВАЛИСЬВМЕСТЕТОЧКА
...
```

## Files

| File | Description |
| ---- | ----------- |
| `crypted-ru.txt` | Encrypted Russian text (input) |
| `find_keyword.py` | Program 1: cryptanalysis, finds keyword and mixed alphabet |
| `crack.py` | Program 2: decrypts the text using found parameters |
| `cipher-params.txt` | Intermediate file: keyword and alphabet (output of Program 1, input of Program 2) |
| `crypted-en.txt` | Encrypted English text (separate puzzle, keyword: COMPILE) |
