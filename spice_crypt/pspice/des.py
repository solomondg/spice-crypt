# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
PSpice® DES variant implementation.

This module implements the custom DES block cipher used by Cadence PSpice
(``CDesEncoder``) for encryption modes 0-2.  It deviates from standard
DES (FIPS 46-3) in its PC-1, PC-2, IP, FP tables and S-boxes, while
retaining standard Expansion, P-box, and rotation schedule.

See ``SPECIFICATIONS/pspice.md`` Section 4 for full details.
"""

from spice_crypt._constants import MASK64
from spice_crypt._des_base import DESBase


class PSpiceDES(DESBase):
    """PSpice DES variant (``CDesEncoder``).

    Uses standard DES structure (right-rotation, no half-swaps, full
    64-bit output) with custom PC-1, PC-2, IP, FP tables and S-boxes.
    """

    # --- Behavioral flags ---
    _SWAP_INPUT = False
    _SWAP_KEY = False
    _ROTATE_RIGHT = True  # Right-rotation in key schedule (same as LTspice)
    _OUTPUT_MASK = MASK64

    # fmt: off

    # S-boxes extracted from PSpiceEnc.exe CDesEncoder_initTables.
    # 8 S-boxes, each 64 entries (4 rows x 16 columns), row-major order.
    DES_SBOXES = [
        # S-box 0
        [
            14, 15, 11,  8,  3, 10,  4, 13,  1,  2,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14, 10,  6, 12,  2, 13,  1, 11,  9,  5,  3,  8,
             4,  1,  6,  2, 11, 15, 12, 14,  8, 13,  9,  7,  3, 10,  5,  0,
            15, 12,  9,  1,  7,  5, 11,  8,  2,  4,  3, 14, 10,  0,  6, 13,
        ],
        # S-box 1
        [
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
            15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        ],
        # S-box 2
        [
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
        ],
        # S-box 3
        [
             4,  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12, 15,
             3, 13,  8, 11,  5,  6, 15,  0,  4,  7,  2, 12,  1, 10, 14,  9,
             2, 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  8,  4,
             1, 15,  0,  6, 10,  3, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
        ],
        # S-box 4
        [
            10, 11,  2, 12,  4,  1,  7,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  1,  5,  0,  2, 12,  4,  7, 13, 15, 10,  3,  9,  8,  6,
             4,  2,  1,  8, 15,  9, 11, 10, 13,  7, 12,  5,  6,  3,  0, 14,
            10,  4,  5,  3, 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9,
        ],
        # S-box 5
        [
            13,  3,  4, 14,  7,  5, 11, 12,  1, 10, 15,  9,  2,  6,  8,  0,
            10, 15,  4,  2,  7, 12, 13, 14,  0,  9,  5,  6,  1, 11,  3,  8,
             9, 12,  3,  7, 14, 15,  5,  2,  8,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12, 11,  9,  5, 15, 10, 14,  1,  7,  6,  0,  8, 13,
        ],
        # S-box 6
        [
             5, 11,  2, 14, 15,  1,  8, 13,  3, 12,  9,  7,  4, 10,  6,  0,
            13,  0, 11,  7,  4,  8,  1, 10, 14,  3,  5, 12,  2, 15,  9,  6,
             1,  4, 11, 13, 12,  3, 14,  7, 10,  8,  6, 15,  0,  5,  9,  2,
             6, 13,  8,  1, 11,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
        ],
        # S-box 7
        [
             3, 12,  8,  4,  6, 15, 11,  1, 10,  9, 13, 14,  5,  0,  2,  7,
             1, 15, 13,  0, 10,  3,  7,  4, 12,  5,  6, 11,  8, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 11,  8, 13, 15, 12,  9,  0,  3,  5,  6, 10,
        ],
    ]

    # Permuted Choice 1 (PC-1) — 0-indexed, converted from 1-indexed binary values.
    DES_PC1_TABLE = [
         0, 57, 49, 41, 33, 25, 17, 56, 48, 40, 32, 24, 16,  8,
         9,  1, 58, 50, 42, 34, 26, 62, 54, 46, 38, 30, 22, 14,
        18, 10,  2, 59, 51, 43, 35, 13,  5, 60, 52, 44, 36, 28,
         6, 61, 53, 45, 37, 29, 21, 20, 12,  4, 27, 19, 11,  3,
    ]

    # Permuted Choice 2 (PC-2)
    DES_PC2_TABLE = [
        13, 16, 10, 23,  0,  4, 22, 18, 11,  3, 25,  7,
         2, 27, 14,  5, 20,  9, 15,  6, 26, 19, 12,  1,
        29, 39, 50, 44, 32, 47, 40, 51, 30, 36, 46, 54,
        45, 48, 38, 55, 33, 52, 41, 49, 35, 43, 28, 31,
    ]

    # Initial Permutation (IP) — PSpice-modified (3 pair-swaps vs standard)
    DES_INITIAL_PERM = [
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 13,  3,
        61, 53, 45, 37, 29, 21, 11,  5,
        55, 63, 47, 39, 31, 23, 15,  7,
        48, 56, 40, 32, 24, 16,  8,  0,
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
    ]

    # Final Permutation (FP / IP^-1) — complementary swaps
    DES_FINAL_PERM = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 22, 54, 14, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        32,  1, 41,  9, 49, 17, 57, 24,
        33,  0, 40,  8, 48, 16, 56, 25,
    ]

    # fmt: on

    def process_block(self, data: bytes, decrypt: bool = True) -> bytes:
        """Decrypt (or encrypt) a 64-byte buffer as 8 independent DES-ECB blocks.

        Args:
            data: 64-byte buffer.
            decrypt: ``True`` for decryption, ``False`` for encryption.

        Returns:
            64-byte result.
        """
        if len(data) != 64:
            raise ValueError("PSpice DES processBlock requires exactly 64 bytes")
        result = bytearray(64)
        for i in range(8):
            block = data[i * 8 : i * 8 + 8]
            block_int = int.from_bytes(block, "little")
            out = self.crypt(block_int, self._key_int, decrypt_mode=decrypt)
            result[i * 8 : i * 8 + 8] = out.to_bytes(8, "little")
        return bytes(result)

    def set_key(self, key_bytes: bytes):
        """Set the DES key from a byte string (up to 8 bytes, zero-padded)."""
        padded = (key_bytes + b"\x00" * 8)[:8]
        self._key_int = int.from_bytes(padded, "little")
        # Force key schedule regeneration
        self.initialized_key = None
