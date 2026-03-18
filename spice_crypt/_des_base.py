# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Base DES engine shared by LTspice and PSpice DES variants.

This module provides :class:`DESBase`, a parameterized DES implementation
whose permutation tables, S-boxes, and behavioral flags are set by
subclasses.  The generic LUT-building machinery and Feistel network
logic live here; each variant only needs to supply its table constants
and override a few flags.
"""

from spice_crypt._constants import MASK32, MASK64

# ---------------------------------------------------------------------------
# Permutation LUT builders (module-level, reusable)
# ---------------------------------------------------------------------------


def _build_permutation_lut(table):
    """
    Precompute a byte-chunked lookup table for a bit permutation.

    Given a permutation table of length N, this builds a list of
    (byte_count) 256-entry sub-tables.  To apply the permutation,
    split the input into 8-bit chunks and OR together the looked-up
    contributions::

        result = 0
        for byte_idx, sub in enumerate(lut):
            result |= sub[(value >> (byte_idx * 8)) & 0xFF]

    This replaces the per-bit loop with a per-byte lookup, giving
    roughly an 8x reduction in Python-level iterations for the hot path.
    """
    max_input_bit = max(table) if table else 0
    input_byte_count = (max_input_bit // 8) + 1

    lut = []
    for byte_idx in range(input_byte_count):
        sub = [0] * 256
        bit_base = byte_idx * 8
        for byte_val in range(256):
            contribution = 0
            for out_bit, in_bit in enumerate(table):
                if bit_base <= in_bit < bit_base + 8 and (byte_val >> (in_bit - bit_base)) & 1:
                    contribution |= 1 << out_bit
            sub[byte_val] = contribution
        lut.append(sub)
    return lut


def _apply_permutation(value, lut):
    """
    Apply a precomputed byte-chunked permutation LUT to an integer value.

    Each entry in *lut* is a 256-element list covering one input byte.
    """
    result = 0
    for byte_idx, sub in enumerate(lut):
        result |= sub[(value >> (byte_idx * 8)) & 0xFF]
    return result


def _build_sbox_direct_lut(sboxes, bit_transform):
    """
    Precompute 8 direct S-box lookup tables (64 entries each).

    *sboxes* is a list of 8 sub-lists, each containing 64 values
    indexed as ``sbox[i][row * 16 + col]`` where row and column are
    derived from the standard DES 6-bit input decomposition.

    For each S-box *i* and each raw 6-bit input value (0-63), the
    table stores the 4-bit output with *bit_transform* already applied.
    """
    tables = []
    for i in range(8):
        t = [0] * 64
        for six_bits in range(64):
            # Row index from bits 5 and 0
            row = ((six_bits & 0x20) >> 5) | ((six_bits & 0x01) << 1)
            # Column index from bits 4, 3, 2, 1
            col = (
                (six_bits & 0x02) << 2
                | (six_bits & 0x04)
                | (six_bits & 0x08) >> 2
                | (six_bits & 0x10) >> 4
            )
            t[six_bits] = bit_transform[sboxes[i][row * 16 + col]]
        tables.append(t)
    return tables


# ---------------------------------------------------------------------------
# Base DES engine
# ---------------------------------------------------------------------------


class DESBase:
    """Parameterized DES implementation.

    Subclasses **must** override the table class attributes
    (``DES_SBOXES``, ``DES_PC1_TABLE``, etc.) and may override the
    behavioral flags (``_SWAP_INPUT``, ``_SWAP_KEY``, ``_ROTATE_RIGHT``,
    ``_OUTPUT_MASK``).

    Precomputed lookup tables are built automatically when a subclass
    is defined (via ``__init_subclass__``).
    """

    # fmt: off

    # --- Table class attributes (subclasses MUST override) ----------------

    # S-boxes: list of 8 lists (64 ints each), indexed [row * 16 + col]
    DES_SBOXES = None

    DES_PC1_TABLE = None        # 56-entry list, 0-indexed bit positions
    DES_PC2_TABLE = None        # 48-entry list
    DES_INITIAL_PERM = None     # 64-entry list
    DES_FINAL_PERM = None       # 64-entry list

    # Standard DES Expansion (E) table — shared default for all variants.
    DES_EXPANSION_TABLE = [
        0x1F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x17, 0x18, 0x19, 0x1A,
        0x1B, 0x1C, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x00,
    ]

    # Standard DES P-box permutation — shared default for all variants.
    DES_PBOX_TABLE = [
        0x0F, 0x06, 0x13, 0x14, 0x1C, 0x0B, 0x1B, 0x10,
        0x00, 0x0E, 0x16, 0x19, 0x04, 0x11, 0x1E, 0x09,
        0x01, 0x07, 0x17, 0x0D, 0x1F, 0x1A, 0x02, 0x08,
        0x12, 0x0C, 0x1D, 0x05, 0x15, 0x0A, 0x03, 0x18,
    ]

    # Standard DES rotation schedule for key schedule.
    ROTATION_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # Bit transform for S-box output (maps 4-bit value → permuted nibble).
    # Standard across all DES variants using this engine.
    DES_BIT_TRANSFORM = [
        0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E,
        0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F,
    ]

    # fmt: on

    # --- Behavioral flags (subclasses override as needed) -----------------

    _SWAP_INPUT: bool = False  # Swap 32-bit halves before IP
    _SWAP_KEY: bool = False  # Swap 32-bit halves before PC-1
    _ROTATE_RIGHT: bool = False  # Rotate key halves right (True) or left (False)
    _OUTPUT_MASK: int = MASK64  # Mask applied to final output (MASK32 truncates)

    # --- Precomputed LUTs (auto-built by __init_subclass__) ---------------

    _PC1_LUT = None
    _PC2_LUT = None
    _EXPANSION_LUT = None
    _PBOX_LUT = None
    _INITIAL_PERM_LUT = None
    _FINAL_PERM_LUT = None
    _SBOX_DIRECT = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Build LUTs from subclass table overrides
        if cls.DES_PC1_TABLE is not None:
            cls._PC1_LUT = _build_permutation_lut(cls.DES_PC1_TABLE)
        if cls.DES_PC2_TABLE is not None:
            cls._PC2_LUT = _build_permutation_lut(cls.DES_PC2_TABLE)
        if cls.DES_EXPANSION_TABLE is not None:
            cls._EXPANSION_LUT = _build_permutation_lut(cls.DES_EXPANSION_TABLE)
        if cls.DES_PBOX_TABLE is not None:
            cls._PBOX_LUT = _build_permutation_lut(cls.DES_PBOX_TABLE)
        if cls.DES_INITIAL_PERM is not None:
            cls._INITIAL_PERM_LUT = _build_permutation_lut(cls.DES_INITIAL_PERM)
        if cls.DES_FINAL_PERM is not None:
            cls._FINAL_PERM_LUT = _build_permutation_lut(cls.DES_FINAL_PERM)
        if cls.DES_SBOXES is not None:
            cls._SBOX_DIRECT = _build_sbox_direct_lut(cls.DES_SBOXES, cls.DES_BIT_TRANSFORM)

    def __init__(self):
        """Initialize the DES cipher."""
        self.subkeys = None
        self.initialized_key = None

    # --- Key schedule -----------------------------------------------------

    @staticmethod
    def _swap_halves(value):
        """Swap the lower and upper 32 bits of a 64-bit value."""
        return (value >> 32) | ((value & MASK32) << 32)

    @staticmethod
    def _rotate_halves_right(value, count):
        """Rotate the two 28-bit halves of the key material right."""
        lower = value & 0xFFFFFFF
        upper = (value >> 28) & 0xFFFFFFF
        complement = 28 - count
        lower = ((lower >> count) | (lower << complement)) & 0xFFFFFFF
        upper = ((upper >> count) | (upper << complement)) & 0xFFFFFFF
        return lower | (upper << 28)

    @staticmethod
    def _rotate_halves_left(value, count):
        """Rotate the two 28-bit halves of the key material left."""
        lower = value & 0xFFFFFFF
        upper = (value >> 28) & 0xFFFFFFF
        complement = 28 - count
        lower = ((lower << count) | (lower >> complement)) & 0xFFFFFFF
        upper = ((upper << count) | (upper >> complement)) & 0xFFFFFFF
        return lower | (upper << 28)

    def generate_key_schedule(self, key):
        """Generate round keys (key schedule) for the algorithm."""
        k = self._swap_halves(key) if self._SWAP_KEY else key
        reduced_key = _apply_permutation(k, self._PC1_LUT)

        rotate = self._rotate_halves_right if self._ROTATE_RIGHT else self._rotate_halves_left

        subkeys = []
        for round_num in range(16):
            reduced_key = rotate(reduced_key, self.ROTATION_TABLE[round_num])
            subkeys.append(_apply_permutation(reduced_key, self._PC2_LUT))
        self.subkeys = subkeys

    # --- Feistel round function -------------------------------------------

    def feistel_function(self, right_half, round_key):
        """
        Apply the Feistel (F) function for a single round.

        1. Expansion of the 32-bit right half to 48 bits
        2. XOR with the round key
        3. S-box substitution (48 bits to 32 bits)
        4. P-box permutation
        """
        xor_val = _apply_permutation(right_half, self._EXPANSION_LUT) ^ round_key

        sbox_direct = self._SBOX_DIRECT
        sbox_output = 0
        for i in range(7, -1, -1):
            sbox_output = sbox_direct[i][(xor_val >> (i * 6)) & 0x3F] | (sbox_output << 4)

        return _apply_permutation(sbox_output, self._PBOX_LUT)

    # --- Block encrypt / decrypt ------------------------------------------

    def crypt(self, input_block, key, decrypt_mode=False):
        """
        Perform DES encryption or decryption on a 64-bit block.

        Args:
            input_block: 64-bit input block to encrypt/decrypt
            key: 64-bit key (56 bits used, 8 bits parity)
            decrypt_mode: Flag to indicate operation mode

        Returns:
            Integer result, masked by ``_OUTPUT_MASK``.
        """
        if self.initialized_key != key:
            self.generate_key_schedule(key)
            self.initialized_key = key

        block = self._swap_halves(input_block) if self._SWAP_INPUT else input_block
        permuted = _apply_permutation(block, self._INITIAL_PERM_LUT)

        left_half = permuted & MASK32
        right_half = (permuted >> 32) & MASK32

        subkeys = self.subkeys
        for round_num in range(16):
            key_idx = 15 - round_num if decrypt_mode else round_num
            f_result = self.feistel_function(right_half, subkeys[key_idx])
            left_half, right_half = right_half, f_result ^ left_half

        combined = (left_half << 32) | right_half
        return _apply_permutation(combined, self._FINAL_PERM_LUT) & self._OUTPUT_MASK
