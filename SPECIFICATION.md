# LTspice® Encryption Specification

**Version**: 1.2.0 ([changelog](#changelog))\
**Author**: Joe T. Sylve, Ph.D. \<joe.sylve@gmail.com\> \
**Repository**: https://github.com/jtsylve/spice-crypt

This document describes the two encryption schemes used by LTspice to protect proprietary model and symbol files (`.CIR`, `.SUB`, `.LIB`, `.ASY`, and others). The text-based format ([Chapter 1](#1-text-based-des-format)) uses a modified variant of the Data Encryption Standard (DES), combined with a pre-DES stream cipher layer and a custom key derivation process. The binary format ([Chapter 2](#2-binary-file-format)) uses a two-layer XOR stream cipher and is unrelated to the DES-based scheme.

[SpiceCrypt](https://github.com/jtsylve/spice-crypt) is a reference implementation of this specification, available as a command-line tool and Python library under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).


## Purpose

Many third-party component vendors distribute SPICE simulation models exclusively as LTspice-encrypted files. This encryption locks the models to a single proprietary simulator, preventing their use in open-source and alternative tools such as NGSpice, Xyce, PySpice, and others.

This specification is published in service of two goals:

- **Interoperability**: Documenting the encryption schemes allows developers of alternative SPICE simulators to support lawfully obtained encrypted models. The accompanying [SpiceCrypt](README.md) reference implementation demonstrates working decryption based on this specification.
- **Encryption research**: Both schemes rely on security through obscurity -- the key material is stored in the clear alongside the ciphertext, and neither scheme provides meaningful cryptographic protection (see Sections [1.8](#18-security-assessment) and [2.5](#25-security-assessment)). Documenting these properties illustrates how proprietary encryption schemes deviate from established standards.

Both activities are specifically permitted by law:

- **United States**: [17 U.S.C. § 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention of technological protection measures for the purpose of achieving interoperability between independently created programs, and Section 1201(f)(2) explicitly allows distributing the tools developed for this purpose. [§ 1201(g)](https://www.law.cornell.edu/uscode/text/17/1201) further permits circumvention conducted in good-faith encryption research and allows dissemination of the findings.
- **European Union**: [Article 6 of the Software Directive (2009/24/EC)](https://eur-lex.europa.eu/eli/dir/2009/24/oj) permits decompilation and reverse engineering when indispensable to achieve interoperability with independently created programs. Article 6(3) provides that this right cannot be overridden by contract.


## Contributors

- **Joe T. Sylve, Ph.D.** -- Research and documentation of the text-based DES encryption format ([Chapter 1](#1-text-based-des-format)).
- **Lucas Gerads** -- Research and documentation of the Binary File encryption format ([Chapter 2](#2-binary-file-format)).

## License

Copyright © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>

This document is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/) (CC-BY-4.0). You are free to share and adapt this material for any purpose, including commercial use, provided appropriate credit is given.

## 1. Text-Based DES Format

This chapter describes the text-based encryption format. Encrypted files in this format contain hex-encoded ciphertext processed through a pre-DES stream cipher and a modified DES block cipher. Each deviation from standard DES is explicitly noted.

### 1.1 Encrypted File Format

An LTspice encrypted file in the text-based format is a plain-text file with the following structure:

```
* LTspice Encrypted File
*
* This encrypted file has been supplied by a 3rd
* party vendor that does not wish to publicize
* the technology used to implement this library.
*
* Permission is granted to use this file for
* simulations but not to reverse engineer its
* contents.
*
* [Header comments...]
*
* Begin:
  A7 CD 92 6F EA 22 42 3D 95 5E D2 59 B6 03 E5 31
  67 06 C2 AF 8A BB 32 98 00 15 89 AF C1 15 0C D9
  ... more hex data ...
* End <v1> <v2>
```

**Header**: The first 9 lines (from `* LTspice Encrypted File` through `* contents.`) are a fixed header that LTspice validates exactly; files with modified or missing header lines are rejected. The `* Begin:` marker is matched case-insensitively.

**Hex payload**: After the `* Begin:` marker, the file contains space-separated hexadecimal byte values. Each pair of hex characters represents one byte. Whitespace (spaces and newlines) separates individual byte values. Lines beginning with `*` within the payload are comments and are skipped.

**Payload structure**: The hex payload is consumed as a flat stream of bytes, grouped into 8-byte (64-bit) blocks:

| Block range  | Count     | Purpose                                |
|-------------|-----------|----------------------------------------|
| 0 -- 127    | 128 blocks (1024 bytes) | Crypto table (key material)   |
| 128+        | Variable  | Ciphertext blocks                      |

If the final ciphertext block contains fewer than 8 bytes, it is discarded -- the partial bytes are included in the ciphertext CRC but are not decrypted. In practice, LTspice always produces payloads that are exact multiples of 8 bytes.

**End line**: The `* End` line contains two unsigned 32-bit decimal integers, `v1` and `v2`, which are CRC-32-based verification checksums (see [Section 1.6](#16-integrity-verification)).

### 1.2 Key Derivation

The 64-bit DES key and the initial stream cipher state are derived entirely from the 1024-byte crypto table (the first 128 blocks of the payload).

#### 1.2.1 Byte Checksums (Stream Cipher Seeds)

The table bytes are split by parity of their index position. Two 8-bit checksums are computed:

```
even_byte_sum = (table[0] + table[2] + table[4] + ... + table[1022]) mod 256
odd_byte_sum  = (table[1] + table[3] + table[5] + ... + table[1023]) mod 256
```

These are then XOR'd with fixed constants to produce the initial stream cipher state values:

```
odd_byte_checksum  = odd_byte_sum  XOR 0x54
even_byte_checksum = even_byte_sum XOR 0xE7
```

The `even_byte_checksum` acts as a fixed increment and `odd_byte_checksum` acts as a running accumulator in the stream cipher (see [Section 1.3](#13-pre-des-stream-cipher-layer)).

#### 1.2.2 DES Key Construction

The table is also processed at the 64-bit (qword) level. It is treated as 64 groups of 16 bytes (two little-endian 64-bit words per group). The even-offset and odd-offset qwords are accumulated separately:

```
qword_sum_even = 0
qword_sum_odd  = 0

for i in range(0, 1024, 16):
    qword_sum_even += uint64_le(table[i   : i+8])
    qword_sum_odd  += uint64_le(table[i+8 : i+16])

# All arithmetic is mod 2^64
combined = (qword_sum_even + qword_sum_odd) mod 2^64
```

Two 16-bit words are extracted from the combined sum:

```
qword_low_word  = combined & 0xFFFF           # bits [15:0]
qword_high_word = (combined >> 32) & 0xFFFF   # bits [47:32]
```

These are XOR'd with 32-bit constants and combined into the 64-bit DES key:

```
key_low  = qword_low_word  XOR 0x66E22120
key_high = qword_high_word XOR 0x20E905C8
key      = (key_high << 32) | key_low
```

> **Note on key entropy**: Although the key is 64 bits wide, it is derived from only two independent 16-bit values (extracted from bits [15:0] and [47:32] of the combined qword sum). Bits [31:16] and [63:48] of each key half are entirely determined by the fixed XOR constants. The effective key entropy is therefore at most 32 bits, significantly less than the 56-bit effective key size of standard DES.

#### 1.2.3 Unused Intermediate Passes

The original LTspice binary contains two additional passes over the crypto table whose results are computed but never used:

- **Pass 2 (byte-group sums)**: The table is treated as 256 groups of 4 bytes. Four positional accumulators sum the bytes at each offset within the groups, and the totals are added together. The result is discarded.
- **Pass 3 (word-group sums)**: The table is treated as 128 groups of 8 bytes (four little-endian 16-bit words per group). Four positional accumulators sum the words at each offset, and the totals are added together. The result is discarded.

Additionally, after all passes complete, a single DES encryption call is made using the combined pass-2 and pass-3 intermediate values as input. The 32-bit result is stored but never read during decryption; it has no effect on the algorithm's output. All of the above may be vestiges of a previous version of the algorithm or deliberate obfuscation.

### 1.3 Pre-DES Stream Cipher Layer

Before each 8-byte ciphertext block is passed to the DES decryption function, a stream cipher layer XORs each byte of the block with a byte selected from the crypto table. This layer uses two state variables, `odd_byte_checksum` and `even_byte_checksum`, initialized during key derivation ([Section 1.2.1](#121-byte-checksums-stream-cipher-seeds)).

For each byte `i` (0 through 7) within a block:

```
odd_byte_checksum = (odd_byte_checksum + even_byte_checksum) mod 2^32
table_index       = (odd_byte_checksum mod 0x3FD) + 1
block[i]         ^= crypto_table[table_index]
```

Key observations:

- **`even_byte_checksum` is constant** -- it is set once during key derivation and never modified. It serves as a fixed additive step.
- **`odd_byte_checksum` is a running accumulator** -- it advances by `even_byte_checksum` for every byte processed across all blocks. Its arithmetic is mod 2^32 (it is promoted from its initial 8-bit value to a 32-bit accumulator on the first addition).
- **Table index range**: The modulus `0x3FD` (1021) combined with the `+1` offset produces indices in the range [1, 1021]. Index 0 is never used.
- **State carries across blocks** -- the checksum state is not reset between blocks, making this a proper stream cipher where the keystream depends on the block position.

After the XOR pass, the modified 8-byte block is interpreted as a little-endian 64-bit integer and passed to the DES decryption function.

### 1.4 DES Variant: Deviations from FIPS 46-3

The core block cipher is a 16-round Feistel network structurally similar to DES (FIPS 46-3), using the same permutation tables (IP, IP^-1, E, P, PC-1, PC-2) and S-boxes. However, the LTspice implementation introduces several deviations from the standard.

#### 1.4.1 Pre-Permutation Half-Swap (Input Block)

**Standard DES**: The 64-bit plaintext/ciphertext block is passed directly to the Initial Permutation (IP).

**LTspice variant**: Before applying IP, the lower 32 bits and upper 32 bits of the input block are swapped:

```
swapped = (input >> 32) | ((input & 0xFFFFFFFF) << 32)
permuted = IP(swapped)
```

This means the DES round function operates on bit-transposed data relative to what standard DES would process given the same input.

#### 1.4.2 Pre-PC-1 Half-Swap (Key Schedule)

**Standard DES**: The 64-bit key is passed directly to Permuted Choice 1 (PC-1) to extract the 56-bit key material.

**LTspice variant**: Before applying PC-1, the same lower/upper 32-bit half-swap is applied to the key:

```
swapped_key = (key >> 32) | ((key & 0xFFFFFFFF) << 32)
reduced_key = PC1(swapped_key)
```

This effectively remaps which key bits feed into which positions of the 56-bit reduced key.

#### 1.4.3 Reversed Key Rotation Direction

**Standard DES**: During key schedule generation, the two 28-bit halves of the reduced key (C and D) are **left-rotated** by the amounts specified in the rotation table: `[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]`.

**LTspice variant**: The two 28-bit halves are **right-rotated** by the same amounts.

```
# Standard DES (left rotate):
lower = ((lower << count) | (lower >> (28 - count))) & 0x0FFFFFFF

# LTspice variant (right rotate):
lower = ((lower >> count) | (lower << (28 - count))) & 0x0FFFFFFF
```

This produces an entirely different set of 16 round subkeys from the same starting key material.

#### 1.4.4 Output Truncation

**Standard DES**: After the final permutation (IP^-1), the full 64-bit result is returned as the ciphertext/plaintext block.

**LTspice variant**: Only the low 32 bits of the IP^-1 output are retained. The upper 32 bits are discarded:

```
result = FP(combined) & 0xFFFFFFFF   # only low 32 bits
```

This is a critical difference: each 64-bit ciphertext block decrypts to only a 32-bit (4-byte) plaintext block, halving the output size relative to the input.

#### 1.4.5 Summary of Unmodified DES Components

The following components are identical to standard DES:

| Component | Description |
|-----------|-------------|
| Initial Permutation (IP) | Standard 64-bit IP table |
| Final Permutation (IP^-1) | Standard 64-bit FP table |
| Expansion (E) | Standard 32-to-48-bit expansion |
| S-boxes (S1--S8) | Standard 8 S-boxes, 6-bit input to 4-bit output |
| P-box (P) | Standard 32-bit permutation |
| PC-1 | Standard 64-to-56-bit permuted choice |
| PC-2 | Standard 56-to-48-bit permuted choice |
| Rotation schedule | Same counts: [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] |
| Feistel structure | Standard 16-round Feistel network |
| Decrypt mode | Standard subkey reversal (use subkeys 15..0) |

#### 1.4.6 Combined Effect

The half-swaps (Sections [1.4.1](#141-pre-permutation-half-swap-input-block) and [1.4.2](#142-pre-pc-1-half-swap-key-schedule)) and the reversed rotation ([Section 1.4.3](#143-reversed-key-rotation-direction)) together mean that even with the same key and plaintext, the LTspice variant produces completely different round computations and outputs compared to standard DES. These modifications are not equivalent to any simple re-keying or re-ordering of the standard algorithm. The output truncation ([Section 1.4.4](#144-output-truncation)) further means the cipher has fundamentally different input/output dimensions: 64 bits in, 32 bits out -- making it a one-way compression function rather than a bijective block cipher.

### 1.5 Block Decryption Pipeline

For each 8-byte ciphertext block (blocks 128 onward), the full decryption pipeline is:

```
1. Read 8 bytes of ciphertext from the hex payload.
2. Apply the pre-DES stream cipher:
   For each byte i = 0..7:
     a. odd_byte_checksum += even_byte_checksum  (mod 2^32)
     b. table_index = (odd_byte_checksum mod 0x3FD) + 1
     c. block[i] ^= crypto_table[table_index]
3. Interpret the 8-byte modified block as a little-endian uint64.
4. Apply the LTspice DES variant in decrypt mode:
     a. Swap the low and high 32-bit halves of the input.
     b. Apply the Initial Permutation (IP).
     c. Split into left (L) and right (R) 32-bit halves.
     d. For 16 rounds (using subkeys in reverse order 15..0):
        - new_R = L XOR F(R, subkey[round])
        - new_L = R
     e. Combine: (L << 32) | R
     f. Apply the Final Permutation (IP^-1).
     g. Mask to 32 bits (discard upper half).
5. Output the 32-bit result as 4 little-endian bytes of plaintext.
```

The plaintext output is therefore half the size of the ciphertext input (4 bytes out per 8 bytes in, excluding the 1024-byte crypto table).

### 1.6 Integrity Verification

Two CRC-32 checksums are maintained incrementally during decryption:

- **`plaintext_crc`**: CRC-32 of all decrypted 4-byte output blocks, computed sequentially.
- **`ciphertext_crc`**: CRC-32 of all 8-byte ciphertext blocks (after block 127), computed sequentially.

After all blocks are processed, two verification values are derived:

```
table_word_44 = uint32_le(crypto_table[0x44 : 0x48])
table_word_94 = uint32_le(crypto_table[0x94 : 0x98])

v1 = plaintext_crc  XOR 0x7A6D2C3A XOR table_word_44
v2 = ciphertext_crc XOR 0x4DA77FD3 XOR table_word_94
```

These values are compared against the two integers on the `* End` line of the file. A mismatch indicates data corruption or an incorrect decryption implementation.

> **Validation order**: LTspice performs a two-pass validation: the first pass decrypts the entire file and verifies the CRC checksums against the `* End` line. Only if they match does a second pass produce decrypted output. Files with CRC mismatches are rejected entirely.

### 1.7 S-Box Layout

The S-box data is stored in a flat array with 1-based indexing (index 0 is padding). Each S-box maps a 6-bit input to a 4-bit output. The 6-bit input is decomposed as:

```
row    = (bit5 << 0) | (bit0 << 1)                           # 2 bits from MSB and LSB
column = (bit1 << 3) | (bit2 << 2) | (bit3 << 1) | bit4     # 4 bits from middle, reversed
```

> Note: Both the row and column bit orderings are reversed compared to standard DES. In standard DES, row = {bit5, bit0} (bit5 as MSB) and column = {bit4, bit3, bit2, bit1} (bit4 as MSB). In this implementation, bit0 is the MSB of row and bit1 is the MSB of column. The interleaved S-box storage and bit-transform together compensate for this, producing the same net substitution values as standard DES S-boxes.

The S-box value is looked up at flat-array offset:

```
offset = (36 * column) + (9 * row) + sbox_index + 1
```

where `sbox_index` ranges from 0 to 7. This interleaved storage format differs from the conventional per-S-box matrix layout in DES literature, but produces the same mapping.

After lookup, the 4-bit S-box output is passed through a bit-transform table that reverses the bit order:

```
DES_BIT_TRANSFORM[n]:
  0→0, 1→8, 2→4, 3→C, 4→2, 5→A, 6→6, 7→E,
  8→1, 9→9, A→5, B→D, C→3, D→B, E→7, F→F
```

This is equivalent to reflecting bits [3:0] to [0:3] (i.e., bit-reversal within the nibble). This transform is folded into the S-box output as part of the implementation, but the net result of S-box + transform produces the same 4-bit substitution values as standard DES S-boxes -- the transform compensates for the interleaved storage format.

### 1.8 Security Assessment

From a cryptographic perspective:

- **Low effective key entropy**: The DES key is derived from only 32 bits of independent data (two 16-bit words extracted from the crypto table checksum). This is well below the 56-bit effective key size of standard DES and far below modern standards.
- **Static key material in cleartext**: The entire 1024-byte crypto table from which the key is derived is stored in the clear as the first 128 blocks of the payload. Anyone with knowledge of the key derivation algorithm can compute the key.
- **Deterministic stream cipher**: The pre-DES XOR layer's keystream is fully determined by the crypto table, which is public. It adds no additional security beyond the DES layer.
- **Obfuscation, not encryption**: The security of this scheme relies entirely on secrecy of the algorithm (security through obscurity) rather than secrecy of the key. Once the algorithm is known, any encrypted file can be decrypted without any secret.

## 2. Binary File Format

This chapter describes the "Binary File" encryption format, a two-layer XOR stream cipher unrelated to the DES-based scheme in [Chapter 1](#1-text-based-des-format). The substitution table and key validation table referenced below are fixed constants extracted from the LTspice binary; see [Appendix A](#appendix-a-binary-file-key-validation-table) and [Appendix B](#appendix-b-binary-file-substitution-table) for the full data.

### 2.1 File Structure

A Binary File is identified by a 20-byte signature and has the following layout:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 20 | Signature: `\r\n<Binary File>\r\n\r\n\x1a` |
| 20 | 4 | `key1` (unsigned 32-bit little-endian integer) |
| 24 | 4 | `key2` (unsigned 32-bit little-endian integer) |
| 28 | Variable | Encrypted body (byte stream) |

The signature in hex is `0D 0A 3C 42 69 6E 61 72 79 20 46 69 6C 65 3E 0D 0A 0D 0A 1A`. The trailing `0x1A` (ASCII SUB / Ctrl-Z) causes legacy programs that treat it as an end-of-file marker to stop reading, preventing the binary body from being displayed as garbled text.

### 2.2 Key Derivation

The `key1` and `key2` header fields are combined to derive the two parameters of the keystream generator: a `base` index and a `step` value.

#### 2.2.1 Base Index Lookup

A check value is computed:

```
check = key1 XOR key2
```

This check value is looked up in a fixed 100-entry validation table (see [Appendix A](#appendix-a-binary-file-key-validation-table)). Each entry maps a 32-bit check value to a 32-bit base value used as the starting index into the substitution table. If the check value is not found in the table, the file cannot be decrypted (the key pair is unrecognized).

#### 2.2.2 Step Value Selection

The step value is selected from a 26-entry table indexed by `key2 mod 26`:

| Index | Step | Index | Step | Index | Step |
|-------|------|-------|------|-------|------|
| 0     | 1    | 9     | 23   | 18    | 61   |
| 1     | 2    | 10    | 29   | 19    | 67   |
| 2     | 3    | 11    | 31   | 20    | 71   |
| 3     | 5    | 12    | 37   | 21    | 73   |
| 4     | 7    | 13    | 41   | 22    | 79   |
| 5     | 11   | 14    | 43   | 23    | 83   |
| 6     | 13   | 15    | 47   | 24    | 89   |
| 7     | 17   | 16    | 53   | 25    | 97   |
| 8     | 19   | 17    | 59   |       |      |

Entry 0 is 1; entries 1 through 25 are the first 25 prime numbers.

The substitution table modulus is 2593, which is itself prime. Since every step value in the table is coprime to 2593 (each is either 1 or a prime less than 2593), the linear congruential index sequence `(base + step × N) mod 2593` is guaranteed to have full period -- all 2593 table entries are visited exactly once before the sequence repeats.

### 2.3 Decryption

Each byte of the encrypted body (from offset 28 onward) is decrypted independently. For body byte at index `N` (0-based):

```
decrypted[N] = encrypted[N] XOR key2_bytes[N mod 4] XOR sbox[(base + step × N) mod 2593]
```

where:

- **`key2_bytes`** are the 4 raw little-endian bytes of the `key2` header field, applied cyclically.
- **`sbox`** is a fixed 2593-byte substitution table (see [Appendix B](#appendix-b-binary-file-substitution-table)).
- **`base`** and **`step`** are derived from the header as described in [Section 2.2](#22-key-derivation).

The two XOR layers are:

1. **Cyclic key XOR**: Each byte is XOR'd with one of the 4 bytes of `key2`, cycling every 4 bytes. This is equivalent to repeating the `key2` value as a 4-byte mask across the entire body.

2. **S-box keystream XOR**: Each byte is XOR'd with a value from the 2593-byte substitution table. The index into this table advances linearly: starting at `base`, incrementing by `step` each byte, modulo 2593. The full-period property of this sequence (see [Section 2.2.2](#222-step-value-selection)) means the keystream repeats only after 2593 bytes.

Both layers commute (XOR is associative and commutative), so they can be applied in either order or combined into a single pass.

> **Note on index arithmetic**: The index expression `base + step × N` is computed using 32-bit unsigned arithmetic. For files exceeding approximately 42 MB (with step=97), the multiplication wraps modulo 2^32, producing a different index sequence than the mathematical formula. Encrypted files in practice are well below this threshold.

### 2.4 Integrity Verification

Two verification values are computed over the decrypted output:

- **CRC-32**: A standard CRC-32 checksum (ISO 3309 / ITU-T V.42) of the entire decrypted byte stream.
- **Rotate-left hash**: An additive hash where each decrypted byte is rotated left within a 32-bit word by a position-dependent shift before being accumulated:

```
rotate_hash = 0
for i, byte in enumerate(decrypted):
    shift = (i + 1) mod 32
    rotated = rotate_left_32(byte, shift)
    rotate_hash = (rotate_hash + rotated) mod 2^32
```

where `rotate_left_32(value, shift)` performs a 32-bit left rotation. When `shift` is 0, the byte value is added directly without rotation.

Unlike the text-based format ([Section 1.6](#16-integrity-verification)), the Binary File format does not embed expected checksum values in the file. The computed values are available for external validation only.

### 2.5 Security Assessment

From a cryptographic perspective:

- **XOR-only cipher**: The entire scheme consists of XOR operations with a deterministic keystream. There is no block cipher or nonlinear transformation applied to the plaintext.
- **Static, embedded key material**: Both the substitution table and the key validation table are fixed constants embedded in the LTspice binary. The per-file keys (`key1`, `key2`) are stored in the clear in the file header.
- **Extremely small keyspace**: With only 100 valid check values in the key table and 26 possible step values, there are at most 2,600 distinct decryption configurations. Exhaustive search is trivial even without knowledge of the algorithm.
- **Fully deterministic**: Given the header fields, the entire keystream is determined. No external secret is required for decryption.

## Appendix A: Binary File Key Validation Table

The key validation table contains 100 entries. Each entry is an 8-byte record consisting of a 32-bit check value followed by a 32-bit base value, both in little-endian byte order. The check value is matched against `key1 XOR key2` from the file header; the corresponding base value provides the starting index into the substitution table.

The table is presented below as raw hexadecimal bytes, 32 bytes (4 entries) per line. Whitespace is for readability only.

```
c0bc4523 64070000 8e725b71 1e060000 96313950 0c060000 fe701206 5c060000
73154e5e 41000000 49199c73 54080000 c9acf402 13030000 63bf893a 84010000
5ec00c30 f9040000 45b8d307 30090000 7c55821c 1e030000 8567a56f be050000
26df2d7f 64070000 2e79d827 36000000 77f6040d a4000000 897b2a22 dd030000
07531c2e b7020000 8faa374c 27070000 f8df310d c9030000 165f0b70 5a070000
f6951b3f 77010000 2a9c0f30 d0080000 d4059268 0b090000 dc2e6733 51060000
26f04935 ee040000 e0803a2b b6030000 34ede626 0e000000 c6688d19 39020000
9b3d0621 6a030000 deb6ee5c 14070000 0dbc3c39 b7080000 4ae7555e e3020000
7f209f12 84020000 b293ae65 da000000 68add77c 27050000 e2f5500b 04030000
286b6139 7a050000 1d86037e e4020000 99edf925 c1030000 2f37923a 210a0000
1b9ca56c 4f060000 6123102d 98060000 75a0ac00 e3040000 a955a139 8b050000
1b6e0308 0d020000 2412be4f 28030000 ef3ea915 28050000 3d399928 da020000
488ba158 d2070000 e55f1948 a7060000 b7bf0164 b4020000 0e7c6c11 3f000000
d3e7ca0e 18030000 dd9b563f 4b040000 25b7da40 15040000 2cb30810 64050000
1c8bb55f ec080000 90dc0c41 7e080000 b562b603 66020000 a3091502 d5010000
c13e3e11 41080000 f9faf94c 03060000 3515e77f c5020000 1fdd2f4f be010000
2501db03 5e030000 2ed9012e 39040000 cc92b36a dd080000 bdeb3f05 fd050000
6857de4e 8c080000 0d50432e 9a090000 a65a7f3e 5d050000 ce61393d 9d040000
c7d9647b 83090000 5511977e d2070000 9770f478 cd070000 4e0dd50a 18080000
bf367f52 51070000 0a2d1a31 1f0a0000 7e3c624d a0030000 72ecee2a 55010000
2e479317 db010000 80fe1939 cd040000 de1a5f18 d3000000 9b54c57b 45040000
d771f002 ba010000 d480f676 98030000 e1a75468 52000000 41b2a45f 0a020000
00217632 f9010000 26bed462 66020000 8edee75e 0b020000 f0409d35 6c070000
bbd37845 41050000 4161cd03 4e090000 24780167 cd010000 dd4d1864 9c070000
5513ad07 0e060000 4d99db00 1d060000 9b368c5b cb040000 79a04907 0c070000
```

To parse entry `i` (0-based), read 8 bytes at offset `i × 8`: the first 4 bytes are the check value and the next 4 bytes are the base value, both as unsigned 32-bit little-endian integers.

## Appendix B: Binary File Substitution Table

The substitution table is a fixed array of 2593 bytes, indexed by `(base + step × N) mod 2593` during decryption (see [Section 2.3](#23-decryption)). The complete table is presented below as raw hexadecimal bytes. Line breaks are for readability only.

```
d55f931826290d5b2961bf26ee61590a58e7b22742b9265466c72f56013d5800
52cff40c0b6f7565e0f4241c1f81fc2a0f6410603af89f5d139320161730ff10
ef101921c1976b254d7b525de8fafb0511071c475fad6c1bd2830d11bde37323
e54e2e66ed2d631152268548e8fe7035f924aa1ca1006572d7869c0acf843d35
c729724d00e85b31bde6963f1f11257542a1820523aec615214e7d7594707712
2e1d3c7b0143a211b3f1733d3e814c5b3b3b426fc784945355b14b6c2a4c5b10
881c0079a22c9e491247571699231c4002da0a65e4ca642756079063e728394b
d1f8c738a82d152ccf27aa00cb1d72554a2e7a1ea7ae460b9aa2af0a1158ec6b
a796a23c5789464a31691161ea3725427a370d6052b78e567ea89c54a954495b
53fa3068329a1012e7d595368e357357f91ea5653c87e122b881ce67813ba55e
dfb37f6ccac8257e1a5fc11ee18d8a51ae938a2570665102c8b6c31c808c525e
1894662e98de6d1d4baac43362c2e04c3f8db428e54c743e741acd38e6235765
3cd6ba08a583de19d05b7c27b60dc868f73a6d704f04197c5f6211444a359e58
819e290e4638a77ad86a11307abdce7383bf881d90ecdf17fbf87352627308
0a5ab50516155835714301935b0849903b85be86730bb8567888d5e2199d52ed
21a396c415d37fa74d0015ce6ee223793eb8cc1b0c742f9b27c947d023f4a2d6
1419b3794199a34c4babb09e7d10eee631e8a765470a13b0415a23850a69468f
55514b573c328e963ae3035e49d40ae059c27a7652defcd11b367ee8631c307c
68f354070d797f7b3f24790c2478138e008437d237ad4eef3d16667b2228ce96
4d80ce960b167b49110af20f0c399bb2178aaae438d339e02f2d3e892ca35d5e
7a6ddd2c7bd8ee272ab34b452c55859242e301d86b0d6fca36bfcb2118344d2f
283ffd6071a2cf7f6108580f020178d74381cc517d3ed6f7651da8532c742159
0ab755732541216050ed34e70a3b8d455dee6f4f0e039b622d635bdc2a6f3ee6
191916ac3e6e4dec36a8d99831a3c090774187cc66d517225e461eef71ae64f9
61ae064a08f969341e04ea8b249108227406d9fe54c3b5ad3cc555511c45d65f
4665852d1ecdad601e464e370ae6517f1b0b84580463f68a365b73d825c2d9cb
29a417eb0648a8bf30fd66110793873a154b43225e61c2ed3102c6202f6459ce
1ccf0fda68aa9fb960071a5f141097a64f7fb7db3e4d384e06bffb9f312dbe25
4746a28224c3e52b56bec6473b4c7b8179869bd912831c99579151e13feb2007
3150caf975d79f184ad272864c5b4e527a3a96a3002de65e721d281e24dead8e
07758e1e231b8f2f2b7135c91cc0d140017c511d5d73fbe94b242b0f1e4b61f7
451d9ba32c2b456e325bf89d159d527f6b787dbc381af43d47ca10a532be1f3f
5dddd9691d89d7ec6d0a9bc056637543300cf485459beca1164f964a615dbe7f
3b728cba602109d12db80cd235ac225e614eef2f20d634f0598ad0ec68c37d4e
43f1c31f05fc05b605834f8f446d153d626f01a051a77a9e62b87634288d9c43
7ed2bf0c15136fd23d2aefc2694a3dc94d2e631005f4ff671c085d082b0b3d7a
227dd7540a12f8c8016fb2bd528acbda4fade46a18be480834e7895a0b1f7125
79df51d9619f962c41cb93835a2d41090275cb1c1b55647043f0be5745668f3c
20516a2649730ee709d3a47902c16bc61a1a89856c8b1bae2a4e080a19ec4892
019f8a806878f7cc0236865b4fcded906d6cf7341f3ee3637ad82a0b10eace89
2950db2c7c47ddc862749a6479fdbf97140526d1165b24bf041c31bd0de477aa
78fabaeb45e7c4406811b9b37a708608613c29b12b01780b40d61545018e93d7
747486f249aababe034fff9d0f8e0f783635d66c2e9d07a8287a580a38d460ed
1615ff742bb0de6507a14e7e0481f6a94aeec1c9017a7989146bc533743e9df6
7dc1565277df5f986d3b5d8e12c77c230e3a845772578e4b20abf4cd06353f43
383e538c08bdad8101a5c54b197b7c3d34be258d417bdb901a0910152933ac7f
0b25964f1e580fb338c1bbf7415b6cbc4cf5165b613c14027a2fcda9630a16d0
0cecf26701d11b28688b0c7a57dbb431034b95b17cf7d1ad4b195228010cec03
74d631463955afb613d368270211b69d2bac3d02347f5df50846f5e063eb908e
3c3c0b770aebba2c7d660dcc70fa30044c6696bd176f1de1192ddd83578c2c0d
36c72c9452ef987b19e798c902bc43ef332bad7d1316667366c659bf4017a0e5
14e7819b4e51663918f254171832174d4b4838e7630ca73f193f03513f1f6a2d
1d6156f62c126c78413020cb480d94f86091c96d4a7615ac2cf824871dcdd4e4
5461d0d8295e32530ec805e920c7669641cd4f3428f5e26c785393a377947cc8
7ae47be8113a2c6d7a50c0b72e0f2966255192e060161a776f27c94b3a38147c
2f6880b007191e63526b2bc97ab0b8976b25c5a26baa2e1a3acf22c508861b99
18bc9a927bff42905194af91794e64004675583c7e8cd418171b39e51ad62815
28eb066c25e33ece3b9e8fab69b856a04dd9213b34f1224f614dd36848bd9d23
462c4fbc5b9d932077cdc6896b7de19c3cb4ad9766f48fd525b5f5186c1c2e48
6e0dae38782021e266cce6df593373db63ca4ffc209c09a562b98e747c87ea8e
1c9b4c35344d3e0676d54e8f6211a57132da121f0df087747de7cd865ac5198b
32d4c64239855d32447d702b00ade87d6d77808125ca4394486a86a133a3cf3d
0168d7b43f374d2b1f20b1da3d1c854c262bdd0045d5a6f32938b39414398b39
3df6c7d510049a746e6cfe1421c017d231a0a31951258d891d4702614e3cf04e
0573cb8f131c51f0304d95c0374ddeae200dd9642e3463471212f83953e19fa7
67bac079568f6865538e8825553141fb7b5aacf91bf80ec708d410397dc283ae
5b305cf227f4c1133bde08fb015b39f36cc968076516bc8f1694c42c2abf30dd
751a56040500c3414b8048af27bbf91d562650cb68c74a1076f7e96c5b991b5b
7ce49b0027447f2d13e6f9091df174655578e27425f8f14370d2140d3d32a3ee
7b875aa943609d321263e4e977e106a35f58acf91a37f52275a38a513b8808ec
422bb7363081934c3de441df2ff51f3e15974fdc5378060c5ab4501b0bb2a5e0
5879c94d253499ca326d9ffe2e9f19190efce3da2864896b0a3835740ae07fdb
4fa808991d1e2f7e27d1f4402520eb0d431621c217a3094e62538efc3e9d7b6b
5b03a78074b672e6367f820e3b5b537a0fee67092c220d6076e45b6652191f40
5ca4a0ac33c89d45020e3f7e713bf0880740a4515cc38f997ced956960b96d9f
01f728642f5a35680f5887b80ff30c3f58bebed31990bc2c1ad38c1a2866c76c
37aeebaa41a4815b4d87b27a7ac40c6d59478ba92fda4077396288d8344a322a
2490b35d70e10ae76fa685a4337e1b671c031847668ae10a06983aa778a7b8f3
19527f5008a679256ae3a87c219223a2646909bf66d03ee6014c914166613223
162b744e11a418fa75543f626ee932222b35d5261028cc7c1650fa8e62e3c0d1
51cc4dd863d7ac095da8cd3e2b14d98113b1ed80160a5617605e0bac3741a1de
06eb
```

## Changelog

### 1.2.0

- Broadened file type scope from `.CIR`/`.SUB` to include `.LIB`, `.ASY`, and other encrypted file types.
- Documented the fixed 9-line header validation (Section 1.1).
- Corrected partial final block handling: incomplete blocks are discarded, not zero-padded (Section 1.1).
- Documented the unused DES encryption call in key derivation that consumes pass-2/pass-3 intermediate values (Section 1.2.3).
- Documented two-pass CRC validation behavior (Section 1.6).
- Added note on 32-bit unsigned index arithmetic in the Binary File format (Section 2.3).

### 1.1.0

- Restructured document into two chapters: Chapter 1 (Text-Based DES Format) and Chapter 2 (Binary File Format).
- Added Chapter 2: specification of the Binary File encryption format, including file structure, two-layer XOR stream cipher, key derivation via lookup table, and integrity verification.
- Added Appendix A (Binary File Key Validation Table) and Appendix B (Binary File Substitution Table) with full constant data for independent reimplementation.
- Renumbered all existing sections from 1–8 to 1.1–1.8; subsections renumbered accordingly.

### 1.0.0

- Initial release documenting the text-based DES encryption format.


---
LTspice® is a registered trademark of Analog Devices, Inc.
