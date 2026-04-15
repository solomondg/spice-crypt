# PSpice® Encryption Specification

**Version**: 1.0.0 ([changelog](#changelog))\
**Author**: Joe T. Sylve, Ph.D. \<joe.sylve@gmail.com\> \
**Repository**: https://github.com/jtsylve/spice-crypt

This document describes the six encryption modes used by Cadence PSpice to protect proprietary SPICE model and subcircuit definitions within `.LIB` and other netlist files.  Modes 0–2 use a custom DES variant; modes 3–5 use AES-256 in ECB mode.  All six modes share a common file format ([Chapter 1](#1-file-format)) and a 64-byte block structure ([Chapter 2](#2-block-structure)).

[SpiceCrypt](https://github.com/jtsylve/spice-crypt) is a reference implementation of this specification, available as a command-line tool and Python library under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).


## Purpose

Many third-party component vendors distribute SPICE simulation models exclusively as PSpice-encrypted files.  This encryption locks the models to a single proprietary simulator, preventing their use in open-source and alternative tools such as NGSpice, Xyce, PySpice, and others.

This specification is published in service of two goals:

- **Interoperability**: Documenting the encryption schemes allows developers of alternative SPICE simulators to support lawfully obtained encrypted models.  The accompanying [SpiceCrypt](../README.md) reference implementation demonstrates working decryption based on this specification.
- **Encryption research**: Several of the modes rely on security through obscurity — key material is either hardcoded or derivable from public data, and the effective keyspace is far smaller than the nominal algorithm parameters suggest (see [Chapter 7](#7-security-assessment)).  Documenting these properties illustrates how proprietary encryption schemes deviate from established standards.

Both activities are specifically permitted by law:

- **United States**: [17 U.S.C. § 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention of technological protection measures for the purpose of achieving interoperability between independently created programs, and Section 1201(f)(2) explicitly allows distributing the tools developed for this purpose.  [§ 1201(g)](https://www.law.cornell.edu/uscode/text/17/1201) further permits circumvention conducted in good-faith encryption research and allows dissemination of the findings.
- **European Union**: [Article 6 of the Software Directive (2009/24/EC)](https://eur-lex.europa.eu/eli/dir/2009/24/oj) permits decompilation and reverse engineering when indispensable to achieve interoperability with independently created programs.  Article 6(3) provides that this right cannot be overridden by contract.


## Contributors

- **Joe T. Sylve, Ph.D.** — Research and documentation of the PSpice encryption modes 0–5.

## License

Copyright © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>

This document is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/) (CC-BY-4.0).  You are free to share and adapt this material for any purpose, including commercial use, provided appropriate credit is given.


## 1. File Format

PSpice encrypted files are otherwise-ordinary SPICE netlists in which selected `.SUBCKT` / `.ENDS` and `.MODEL` blocks have been replaced by hex-encoded ciphertext enclosed between delimiter markers.

### 1.1 Delimiter Markers

Each encrypted region begins with a `$CDNENCSTART` variant and ends with the corresponding `$CDNENCFINISH` variant.  The specific marker determines the encryption mode:

| Marker | Mode | Cipher |
|--------|------|--------|
| `$CDNENCSTART` | 0 | DES |
| `$CDNENCSTART_CENC`*V* | 1 | DES |
| `$CDNENCSTART_ADV1` | 2 | DES |
| `$CDNENCSTART_ADV2` | 3 | AES-256 ECB |
| `$CDNENCSTART_ADV3` | 4 | AES-256 ECB |
| `$CDNENCSTART_USER_ADV3` | 4 | AES-256 ECB (user key) |
| `$CDNENCSTART_CENC5` | 5 | AES-256 ECB |

The finish markers follow the same pattern, substituting `FINISH` for `START` (e.g., `$CDNENCFINISH_ADV2`).

The trailing digits in the marker (e.g., `1` in `$CDNENCSTART_ADV1`, `2` in `$CDNENCSTART_ADV2`) constitute the **version string**.  This string is used in key derivation ([Chapter 3](#3-key-derivation)).  For bare `$CDNENCSTART` (mode 0), the version string is empty.

### 1.2 Encrypted Region Layout

Between the start and finish markers, each line contains the hex encoding of one 64-byte encrypted block:

```
$CDNENCSTART_ADV2
a1b2c3d4...  (128 hex characters = 64 bytes)
e5f6a7b8...  (128 hex characters = 64 bytes)
...
$CDNENCFINISH_ADV2
```

Each line is exactly 128 hexadecimal characters (lowercase), representing 64 bytes.  Lines that are not exactly 128 hex characters, or that fail hex decoding, are skipped.

### 1.3 Non-Encrypted Pass-Through

Lines outside `$CDNENCSTART` / `$CDNENCFINISH` pairs are plaintext SPICE netlist content and are not encrypted.  A single file may contain multiple encrypted regions interspersed with plaintext.


## 2. Block Structure

All six modes operate on **64-byte blocks**.  Each 64-byte block has the following internal structure:

| Byte range | Size | Content |
|-----------|------|---------|
| 0–61 | 62 bytes | Payload (plaintext content + padding) |
| 62–63 | 2 bytes | Continuation flag: `0x24 0x2B` (`$+`) signals that the next block's payload continues this block verbatim (see [Section 2.4](#24-line-continuation)).  Any other value means the block terminates its logical line; observed non-continuation values include `$\0`, `\r\0`, and padding-fill letters. |

### 2.1 Header Block

The first encrypted block in each region is a **header block**.  It is not part of the plaintext output; it contains metadata formatted as:

```
0001.0000 <extended_key> 0 -1 novendorinformation
```

where `<extended_key>` is the extended key string derived during key derivation ([Section 3.2](#32-extended-key-metadata-only)).  If the formatted header exceeds 62 bytes (which occurs for modes with longer extended keys), it is truncated to 62 bytes; otherwise it is padded as described in [Section 2.3](#23-padding).  The resulting 64 bytes are encrypted.

During decryption, the header block is decrypted and validated: the known prefix `"0001.0000 "` serves as a sentinel confirming that the correct key was used.  The header is then discarded and is not part of the plaintext output.  The same prefix serves as a known-plaintext crib for key recovery attacks ([Chapter 6](#6-mode-4-key-recovery)).

### 2.2 Content Blocks

After the header block, each subsequent encrypted block carries up to 62 bytes of plaintext content in bytes 0–61.  Bytes 62–63 carry the continuation flag described in [Section 2.4](#24-line-continuation).

### 2.3 Padding

When the plaintext content for a block is shorter than 62 bytes, the following padding scheme is applied:

1. The 6-byte sentinel ` $jbs$` (space followed by `$jbs$`) is written immediately after the content.
2. The remaining bytes (up to position 61) are filled with pseudo-random ASCII characters.  Each fill byte is generated as `(rand() & 0x0F) + base`, where `base` cycles through the values 65 (`A`) through 70 (`F`) in groups of six.
3. Byte 62 is set to null (`0x00`), making the padded content null-terminated within the 63-byte region (bytes 0–62).  However, this null byte is then overwritten by the encoder when it writes bytes 62–63.

During decryption, the padding sentinel ` $jbs$` is searched within bytes 0–61 of each decrypted block.  If found, only the content before the sentinel is used.  Any remaining trailing null bytes are also stripped.

### 2.4 Line Continuation

PSpice source lines longer than 62 characters are split across multiple blocks.  Two continuation mechanisms coexist:

**Tail-marker continuation (byte-limit split).**  When the encoder fills all 62 payload bytes of a block with content from a single source line, it writes `0x24 0x2B` (`$+`) at bytes 62–63 of that block.  The next block's payload (bytes 0–61) begins **mid-content** with no leading marker and is appended to the current logical line verbatim.  Chains of three or more blocks are produced by writing `$+` at the tail of every non-terminal block.

**Leading-`+` continuation (SPICE-syntax continuation line).**  When a source line begins with the standard SPICE continuation marker `+` (ASCII 0x2B), the encoder stores the `+` verbatim at byte 0 of the encoded block.  The block represents a new source line (a continuation of the previous logical statement) and the `+` **must be preserved** in the decoded output — stripping it produces unparseable SPICE for downstream simulators, since `+` is syntactically required to denote the continuation.  A decoder may still use the leading `+` as a *signal* that this block belongs to the previous logical statement for buffering purposes, but the character itself is part of the plaintext and round-trips to output.

The two mechanisms are mutually exclusive in practice: a block whose tail is `$+` is always followed by a block that does **not** begin with `+`, and vice versa.  Decoders must implement both.

When a line exceeds 124 characters, the encoder searches for a natural break point (a space or comma) within the first 124 characters and splits there; the resulting blocks still use the tail-marker or leading-`+` mechanisms above.

Source-file line terminators (`\r\n` on Windows, `\n` on Unix) are preserved as literal bytes within the block payload.  Decoders targeting a specific platform should normalise these after reassembling logical lines.


## 3. Key Derivation

Each mode derives two key strings from a combination of hardcoded constants, the marker's version string, and (for mode 4) optional user-provided key bytes.

### 3.1 Short Key (Encryption Key)

The **short key** is the actual key passed to the cipher engine.  It is an ASCII byte string constructed as described in the table below.

| Mode | Short key |
|------|-----------|
| 0 | `0a0vr7jo` (literal, 8 bytes) |
| 1 | `1b1w` + *N* |
| 2 | `1b1x` + *N* |
| 3 | `8gM2` + *N* |
| 4 (no user key) | `8gM2` + *N* |
| 4 (with user key) | XOR(`8gM2`, *user*[0:4]) + *N* |
| 5 | `1yti` + *N* |

where *N* is the **version suffix**, a decimal integer computed as:

```
N = atoi(version_string) + 999
```

For mode 0, the version string is empty and the short key is the literal `0a0vr7jo` with no suffix appended.  For example, if the marker is `$CDNENCSTART_ADV2`, the version string is `"2"`, so *N* = `2 + 999 = 1001`, and the short key for mode 3 is `"8gM21001"` (8 bytes).

### 3.2 Extended Key (Metadata Only)

The **extended key** is written into the encrypted header block ([Section 2.1](#21-header-block)) but is **not used as encryption key material**.  It is constructed as:

| Mode | Extended key |
|------|-------------|
| 0 | `ths0m02ukhy034r6` (literal, 16 bytes) |
| 1 | `uit1n13vliz1` + *N* |
| 2 | `uit1x13vlka1` + *N* |
| 3 | `H41Mlwqaspj1nxasyhq8530nh1r` + *N* |
| 4 (no user key) | `H41Mlwqaspj1nxasyhq8530nh1r` + *N* |
| 4 (with user key) | XOR(`H41Mlwqaspj1nxasyhq8530nh1r`, *user*[4:31]) + *N* |
| 5 | `nhtti50rplx2` + *N* |

### 3.3 Mode 4 User Key XOR

Mode 4 optionally incorporates a user-provided key to modify the base key constants.  The user key is a 31-byte ASCII string loaded from a CSV file identified by the `CDN_PSPICE_ENCKEYS` environment variable.

The CSV file has lines of the form:

```
<file_path> ; <key_bytes>
```

The first entry whose file path does not match the file being decrypted provides the key bytes.

When a user key of at least 4 bytes is available:

1. **Short key modification**: The first 4 bytes of the user key are XOR'd byte-by-byte with the 4-byte short key base `8gM2` (ASCII bytes `0x38 0x67 0x4D 0x32`).  The version suffix *N* is appended after XOR.
2. **Extended key modification**: User key bytes 4 through 30 (up to 27 bytes) are XOR'd byte-by-byte with the 27-byte extended key base `H41Mlwqaspj1nxasyhq8530nh1r` (ASCII).  The version suffix *N* is appended after XOR.

When no user key is available, mode 4 uses the unmodified base keys, identical to mode 3.  Files encrypted with a user key use the `$CDNENCSTART_USER_ADV3` marker; files without use `$CDNENCSTART_ADV3`.


## 4. DES Variant (Modes 0–2)

Modes 0–2 use a custom DES variant that retains the standard 16-round Feistel network structure but differs from FIPS 46-3 in its permutation tables, S-boxes, and key rotation direction.

### 4.1 Key Setup

The short key string (up to 8 bytes) is treated as a sequence of raw bytes.  If shorter than 8 bytes, it is zero-padded on the right to 8 bytes.  The 8-byte value is interpreted as a little-endian 64-bit integer for the DES key schedule.

### 4.2 Block Processing

Each 64-byte encrypted block is processed as **8 independent DES-ECB blocks** of 8 bytes each.  For each 8-byte sub-block:

1. Read 8 bytes from the block.
2. Interpret as a little-endian 64-bit integer.
3. Decrypt (or encrypt) using the PSpice DES variant.
4. Write the 64-bit result back as 8 little-endian bytes.

The full 64-bit DES output is retained (unlike the LTspice variant, which truncates to 32 bits).

### 4.3 Deviations from Standard DES (FIPS 46-3)

The PSpice DES variant shares the same Feistel structure, Expansion (E), P-box, and rotation count schedule as standard DES.  The following components differ:

#### 4.3.1 Custom S-Boxes

All eight S-boxes differ from the standard DES S-boxes.  Each S-box maps a 6-bit input to a 4-bit output using the standard DES decomposition: row = {bit 5, bit 0} (bit 5 is MSB), column = {bit 4, bit 3, bit 2, bit 1} (bit 4 is MSB).  The complete S-box data is given in [Appendix A](#appendix-a-des-s-boxes).

#### 4.3.2 Custom Permuted Choice 1 (PC-1)

The 56-entry PC-1 table, which selects 56 bits from the 64-bit key, differs from the standard DES PC-1.  The complete table (0-indexed bit positions) is:

```
 0, 57, 49, 41, 33, 25, 17, 56, 48, 40, 32, 24, 16,  8,
 9,  1, 58, 50, 42, 34, 26, 62, 54, 46, 38, 30, 22, 14,
18, 10,  2, 59, 51, 43, 35, 13,  5, 60, 52, 44, 36, 28,
 6, 61, 53, 45, 37, 29, 21, 20, 12,  4, 27, 19, 11,  3,
```

#### 4.3.3 Custom Permuted Choice 2 (PC-2)

The 48-entry PC-2 table, which selects 48 bits from the 56-bit reduced key for each round, differs from the standard DES PC-2:

```
13, 16, 10, 23,  0,  4, 22, 18, 11,  3, 25,  7,
 2, 27, 14,  5, 20,  9, 15,  6, 26, 19, 12,  1,
29, 39, 50, 44, 32, 47, 40, 51, 30, 36, 46, 54,
45, 48, 38, 55, 33, 52, 41, 49, 35, 43, 28, 31,
```

#### 4.3.4 Custom Initial Permutation (IP)

The 64-entry Initial Permutation differs from the standard DES IP by three pair-swaps.  The complete table (0-indexed):

```
57, 49, 41, 33, 25, 17,  9,  1,
59, 51, 43, 35, 27, 19, 13,  3,
61, 53, 45, 37, 29, 21, 11,  5,
55, 63, 47, 39, 31, 23, 15,  7,
48, 56, 40, 32, 24, 16,  8,  0,
58, 50, 42, 34, 26, 18, 10,  2,
60, 52, 44, 36, 28, 20, 12,  4,
62, 54, 46, 38, 30, 22, 14,  6,
```

The deviations from the standard DES IP (FIPS 46-3) are three pair-swaps of values (0-indexed positions in the IP table): positions 14 and 22 (values 11 and 13 exchanged), positions 24 and 25 (values 63 and 55 exchanged), and positions 32 and 33 (values 56 and 48 exchanged).

#### 4.3.5 Custom Final Permutation (FP / IP^-1)

The 64-entry Final Permutation is the inverse of the custom IP above:

```
39,  7, 47, 15, 55, 23, 63, 31,
38,  6, 46, 22, 54, 14, 62, 30,
37,  5, 45, 13, 53, 21, 61, 29,
36,  4, 44, 12, 52, 20, 60, 28,
35,  3, 43, 11, 51, 19, 59, 27,
34,  2, 42, 10, 50, 18, 58, 26,
32,  1, 41,  9, 49, 17, 57, 24,
33,  0, 40,  8, 48, 16, 56, 25,
```

#### 4.3.6 Reversed Key Rotation Direction

**Standard DES**: During key schedule generation, the two 28-bit halves (C and D) of the reduced key are **left-rotated** by the amounts in the standard rotation schedule: `[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]`.

**PSpice variant**: The two 28-bit halves are **right-rotated** by the same amounts.  This is the same deviation found in the LTspice DES variant.

```
# Standard DES (left rotate):
half = ((half << count) | (half >> (28 - count))) & 0x0FFFFFFF

# PSpice variant (right rotate):
half = ((half >> count) | (half << (28 - count))) & 0x0FFFFFFF
```

#### 4.3.7 Unmodified DES Components

The following components are identical to standard DES (FIPS 46-3):

| Component | Description |
|-----------|-------------|
| Expansion (E) | Standard 32-to-48-bit expansion |
| P-box (P) | Standard 32-bit permutation |
| Rotation schedule | Same counts: [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] |
| Feistel structure | Standard 16-round Feistel network |
| Output | Full 64-bit result (no truncation) |
| No input half-swap | Input block passed directly to IP (no pre-IP swap) |
| No key half-swap | Key passed directly to PC-1 (no pre-PC-1 swap) |
| Decrypt mode | Standard subkey reversal (use subkeys 15..0) |


## 5. AES-256 ECB (Modes 3–5)

Modes 3–5 use standard AES-256 in Electronic Codebook (ECB) mode, as specified in FIPS 197.  There are no algorithmic deviations from the standard; the cipher itself is unmodified.

### 5.1 Key Construction

The short key string is copied into a 32-byte buffer, zero-padded on the right.  For example, the mode 3 key with version string `"2"` is:

```
Short key string: "8gM21001" (8 ASCII bytes)
32-byte AES key:  38 67 4D 32 31 30 30 31 00 00 00 00 00 00 00 00
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

The standard AES-256 key expansion (FIPS 197, Section 5.2) is then applied to produce the 15 round keys (60 32-bit words).

### 5.2 Block Processing

Each 64-byte encrypted block is processed as **4 independent AES-256-ECB blocks** of 16 bytes each:

1. Divide the 64-byte block into four 16-byte sub-blocks.
2. Decrypt each sub-block independently using AES-256-ECB.
3. Concatenate the four 16-byte results to form the 64-byte decrypted block.

### 5.3 Key Entropy

Although AES-256 nominally provides a 256-bit key, the actual key entropy is much lower:

- **Modes 3 and 5**: The key is entirely determined by the hardcoded base string and the version suffix.  There is zero secret entropy; the key is fully public.
- **Mode 4 without user key**: Identical to mode 3.
- **Mode 4 with user key**: Only 4 bytes of the user key are XOR'd into the short key (the first 4 bytes).  The remaining 24 bytes of the 32-byte AES key are always zero.  The effective keyspace is therefore 2^32, a factor of 2^224 smaller than the 2^256 nominal AES-256 keyspace.


## 6. Mode 4 Key Recovery

The combination of a small effective keyspace (2^32) and a known plaintext crib makes mode 4 user keys recoverable through brute-force search.  For a detailed analysis of the root cause, including the key derivation bug and its implications, see [PSpice Mode 4 Encryption Weakness](pspice-attack-summary.md).

### 6.1 Known Plaintext Crib

The header block ([Section 2.1](#21-header-block)) always begins with the fixed prefix `"0001.0000 "` (10 ASCII bytes: `30 30 30 31 2E 30 30 30 30 20`).  This prefix falls entirely within the first 16-byte AES sub-block of the 64-byte encrypted block, providing a reliable known-plaintext crib.

### 6.2 Key Structure

The 32-byte AES key for mode 4 has the following structure:

| Byte positions | Content |
|---------------|---------|
| 0–3 | Unknown (XOR of `8gM2` with user key bytes 0–3) |
| 4–7 | Version suffix digits (ASCII), e.g., `31 30 30 32` for `"1002"` |
| 8–31 | Zero bytes |

Only bytes 0–3 are unknown.  All other bytes are either known constants (the version suffix) or zero.

### 6.3 Search Procedure

For each candidate value `C` in `[0, 2^32)`:

1. Set bytes 0–3 of the 32-byte key to `C` (little-endian).
2. Perform the AES-256 key expansion.
3. Decrypt the first 16-byte sub-block of the encrypted header.
4. Compare the first 10 bytes of the decrypted result against `"0001.0000 "`.
5. If they match, the candidate is the correct short key prefix.

### 6.4 User Key Recovery

Once the correct short key bytes `S[0:4]` are found:

1. **User key bytes 0–3**: `user[0:4] = XOR(S[0:4], "8gM2")`
2. **User key bytes 4–30**: Decrypt the full header block, extract the extended key string from position 10, strip the version suffix, and XOR with the extended key base `H41Mlwqaspj1nxasyhq8530nh1r` to recover `user[4:31]`.

### 6.5 Key Schedule Optimization

The zero-heavy key structure allows the AES-256 key expansion to be partially simplified.  In the standard key schedule, words `W[0]` through `W[7]` are derived directly from the key bytes.  Since `W[1]` contains only the known version suffix and words `W[2]` through `W[7]` are zero, the first two "epochs" of the key schedule (words `W[8]` through `W[23]`) can be simplified by eliding zero-valued terms.  Subsequent epochs use the standard recurrence.

### 6.6 Default Key Detection

Before initiating the brute-force search, the header block should be tested against the unmodified mode 4 base keys (identical to mode 3).  If the header decrypts successfully with the default keys, no user key was applied, and the file can be decrypted directly without key recovery.


## 7. Security Assessment

### 7.1 Modes 0–2 (DES)

- **Fully deterministic keys**: The short key for modes 0–2 is derived entirely from hardcoded constants and the version string, both of which are visible in the file.  No secret is required for decryption.
- **Weak underlying cipher**: Even if the keys were secret, the custom DES variant operates on 64-bit blocks with at most a 64-bit key, well below modern standards.  The effective key entropy is limited to the 56 bits surviving PC-1, minus any entropy reduction from the ASCII key character set (typically 6–7 bits per byte).
- **Custom tables do not add security**: The non-standard S-boxes, permutation tables, and reversed key rotation change the cipher's bit mappings but do not increase its resistance to known attacks once the tables are published.

### 7.2 Modes 3 and 5 (AES-256, No User Key)

- **Zero-entropy keys**: The AES-256 key is entirely determined by hardcoded constants and the version string.  Any encrypted file can be decrypted without any secret.
- **Misleading key size**: Despite using AES-256, the actual key material occupies at most 8 bytes (the short key string), with the remaining 24 bytes always zero.

### 7.3 Mode 4 (AES-256, User Key)

- **Effective keyspace of 2^32**: Only 4 bytes of the user key affect the encryption key.  The remaining 27 bytes of the user key only affect the extended key in the header metadata.
- **Known plaintext available**: The fixed header prefix `"0001.0000 "` provides a reliable crib for validating candidate keys.
- **Brute-force feasible**: With hardware-accelerated AES (AES-NI or ARM Crypto Extensions) and multi-core parallelism, the 2^32 keyspace can be exhaustively searched in seconds on modern hardware.
- **User key fully recoverable**: Once the short key is found, the full 31-byte user key can be reconstructed from the decrypted header.

### 7.4 General Observations

- **ECB mode weakness**: Both the DES and AES modes use ECB (each sub-block encrypted independently).  Identical plaintext blocks produce identical ciphertext blocks, potentially revealing patterns.
- **No integrity protection**: PSpice encrypted files have no cryptographic authentication (MAC, HMAC, or AEAD).  The header prefix `"0001.0000 "` ([Section 2.1](#21-header-block)) serves as a decryption sentinel but is a fixed constant, not a data-dependent checksum.
- **Obfuscation, not encryption**: For modes 0–3 and 5, the security relies entirely on secrecy of the algorithm and key constants.  Once the algorithm is known, any encrypted file in these modes can be decrypted without any secret.


## Appendix A: DES S-Boxes

The PSpice DES variant uses eight custom S-boxes.  Each S-box maps a 6-bit input to a 4-bit output using the standard DES decomposition: row = {bit 5, bit 0} (bit 5 is MSB), column = {bit 4, bit 3, bit 2, bit 1} (bit 4 is MSB).  Each table below has 4 rows (0–3) and 16 columns (0–15).

> **Note**: The reference implementation stores S-box data in an equivalent but differently-arranged internal format (reversed row/column bit ordering with a 4-bit output transform).  The tables below have been recomputed to use the standard DES decomposition so they can be used directly with any standard DES implementation.

**S-box 0**

```
 7,  8, 12, 10, 13,  6,  2,  0, 15,  4,  5,  9,  1,  3, 11, 14,
 2,  1, 13, 12,  6,  9,  3, 10,  8, 11, 15,  5,  4, 14,  7,  0,
 0,  4,  7,  9, 14,  8,  6, 12, 15, 11,  5, 10,  2, 13,  3,  1,
15,  4, 14,  5,  9, 12, 13,  6,  3,  2, 10,  0,  8,  7,  1, 11,
```

**S-box 1**

```
11, 13, 12,  0,  5, 14,  2,  7,  1,  6, 15, 10,  8,  3,  4,  9,
15,  9,  6,  3,  1,  4, 12, 10,  8, 14, 13,  0,  7, 11,  2,  5,
12,  3, 15,  6,  2,  8,  1, 13, 11,  0,  4,  9, 14,  5,  7, 10,
 0, 10,  5,  9, 14,  3, 11,  4,  7,  1,  2, 12, 13,  6,  8, 15,
```

**S-box 2**

```
11,  4, 12,  3,  0, 10,  6, 15, 14,  1,  2, 13,  9,  7,  5,  8,
 8,  2,  6, 13, 11,  7,  1,  4,  5, 15,  9, 10,  0, 12, 14,  3,
 5,  8,  6, 13,  9,  3, 15,  4,  0, 11, 12,  2,  7, 14, 10,  1,
11, 13,  1, 10,  2,  4, 12,  7,  6,  8, 15,  5,  9,  3,  0, 14,
```

**S-box 3**

```
 2,  5, 12, 10, 11,  4,  6,  3, 14,  8,  0, 13,  7,  1,  9, 15,
 4, 11,  0,  7,  6,  8, 13,  1,  5, 15,  3, 10,  9, 12, 14,  2,
12,  2, 10,  8,  1,  4, 15,  7, 11, 14,  6,  5, 13,  3,  0,  9,
 8,  9,  5,  3,  0, 10, 11,  4, 15,  2, 12, 14,  6, 13,  1,  7,
```

**S-box 4**

```
 5,  1,  2, 11,  4, 12, 14,  7, 13, 10,  8,  0,  3, 15,  6,  9,
 2, 11, 15,  6,  8,  3, 13,  0,  4, 14,  9, 12,  1, 10,  5,  7,
 7, 14,  0, 12,  8, 15,  3,  1, 13, 11,  4,  9, 10,  5,  2,  6,
 5,  8, 13,  6, 10,  4,  3,  0,  2,  7,  1, 15, 12, 11, 14,  9,
```

**S-box 5**

```
11,  8, 14,  4,  2, 15, 13,  1, 12,  5, 10,  6,  7,  9,  3,  0,
 9,  1,  7,  8, 12,  2, 10, 13,  3,  0, 15, 11, 14,  5,  4,  6,
 5,  0, 14,  8,  2, 10, 11, 12, 15,  9,  3, 13,  4,  6,  7,  1,
 2,  5, 13,  6,  4,  8, 10,  1, 12,  7,  9,  0,  3, 14, 15, 11,
```

**S-box 6**

```
10, 12, 15,  2,  4,  9,  1,  6, 13,  3,  8,  5,  7, 14, 11,  0,
 8,  5,  3,  0, 13,  6,  7,  9,  2,  1, 12, 10, 11, 15, 14,  4,
11,  7,  2,  4, 13, 10,  8,  9,  0, 12,  1, 15, 14,  3,  5,  6,
 6,  9, 13,  7,  1,  0,  5, 12, 11, 10,  2,  4,  8, 15, 14,  3,
```

**S-box 7**

```
12,  5,  6, 10,  1, 11, 13,  4,  3,  9, 15,  0,  2,  7,  8, 14,
14,  0,  9, 15,  2,  5,  7, 10, 13,  6,  3, 12,  8, 11,  4,  1,
 8,  3,  5,  1, 11,  6, 14,  9, 15, 10, 12,  7,  0, 13,  2,  4,
 4, 15,  2, 12,  7,  9,  1,  6,  8,  3, 13, 10, 14,  0, 11,  5,
```


## Appendix B: Mode and Marker Summary

| Mode | Cipher | Marker suffix | Short key base | Extended key base | User key? |
|------|--------|---------------|----------------|-------------------|-----------|
| 0 | DES | *(none)* | `0a0vr7jo` | `ths0m02ukhy034r6` | No |
| 1 | DES | `_CENC`*V* | `1b1w` | `uit1n13vliz1` | No |
| 2 | DES | `_ADV1` | `1b1x` | `uit1x13vlka1` | No |
| 3 | AES-256 | `_ADV2` | `8gM2` | `H41Mlwqaspj1nxasyhq8530nh1r` | No |
| 4 | AES-256 | `_ADV3` / `_USER_ADV3` | `8gM2` | `H41Mlwqaspj1nxasyhq8530nh1r` | Optional |
| 5 | AES-256 | `_CENC5` | `1yti` | `nhtti50rplx2` | No |

For modes 1–5, the version suffix *N* = `atoi(version_string) + 999` is appended to both key bases.


## Changelog

### 1.0.0

- Initial release documenting the PSpice encryption file format, block structure, key derivation for all six modes (0–5), DES variant (custom S-boxes, permutation tables, reversed key rotation), AES-256 ECB operation, mode 4 key recovery, and security assessment.


---
PSpice is a trademark of Cadence Design Systems, Inc.
