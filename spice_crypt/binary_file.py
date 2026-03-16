# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Decryption support for LTspice® Binary File format.

This module handles encrypted model files that use the Binary File
format -- a binary encoding with a two-layer XOR stream cipher,
distinct from the text-based hex/DES format handled by the other
modules.

The file structure is:

    Offset  Size  Field
    ------  ----  -----
    0       20    Signature: ``\\r\\n<Binary File>\\r\\n\\r\\n\\x1a``
    20       4    key1 (uint32 LE)
    24       4    key2 (uint32 LE)
    28       ...  Encrypted body (byte stream)

Decryption of each body byte at index *N* (0-based from offset 28):

    decrypted[N] = (encrypted[N] ^ key2_bytes[N & 3])
                 ^ sbox[(base + step * N) % 2593]

where *base* and *step* are derived from the header key fields via
a lookup table, and *sbox* is a fixed 2593-byte substitution table.
"""

import binascii
import struct
from collections.abc import Generator

_MASK32 = 0xFFFFFFFF

# 20-byte file signature
SIGNATURE = b"\r\n<Binary File>\r\n\r\n\x1a"

# fmt: off
# Step values indexed by key2 % 26.
# Entry 0 is 1; entries 1-25 are the first 25 primes.
_STEP_TABLE = (
    1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
)

_SBOX_MODULUS = 2593
# 2593-byte substitution table, indexed by (base + step * N) % 2593.
_SBOX = bytes.fromhex(
    "d55f931826290d5b2961bf26ee61590a58e7b22742b9265466c72f56013d5800"
    "52cff40c0b6f7565e0f4241c1f81fc2a0f6410603af89f5d139320161730ff10"
    "ef101921c1976b254d7b525de8fafb0511071c475fad6c1bd2830d11bde37323"
    "e54e2e66ed2d631152268548e8fe7035f924aa1ca1006572d7869c0acf843d35"
    "c729724d00e85b31bde6963f1f11257542a1820523aec615214e7d7594707712"
    "2e1d3c7b0143a211b3f1733d3e814c5b3b3b426fc784945355b14b6c2a4c5b10"
    "881c0079a22c9e491247571699231c4002da0a65e4ca642756079063e728394b"
    "d1f8c738a82d152ccf27aa00cb1d72554a2e7a1ea7ae460b9aa2af0a1158ec6b"
    "a796a23c5789464a31691161ea3725427a370d6052b78e567ea89c54a954495b"
    "53fa3068329a1012e7d595368e357357f91ea5653c87e122b881ce67813ba55e"
    "dfb37f6ccac8257e1a5fc11ee18d8a51ae938a2570665102c8b6c31c808c525e"
    "1894662e98de6d1d4baac43362c2e04c3f8db428e54c743e741acd38e6235765"
    "3cd6ba08a583de19d05b7c27b60dc868f73a6d704f04197c5f6211444a359e58"
    "819e290e4638a77ad86a11307abdce7383bf881d90ecdf17fbf87352627308"
    "0a5ab50516155835714301935b0849903b85be86730bb8567888d5e2199d52ed"
    "21a396c415d37fa74d0015ce6ee223793eb8cc1b0c742f9b27c947d023f4a2d6"
    "1419b3794199a34c4babb09e7d10eee631e8a765470a13b0415a23850a69468f"
    "55514b573c328e963ae3035e49d40ae059c27a7652defcd11b367ee8631c307c"
    "68f354070d797f7b3f24790c2478138e008437d237ad4eef3d16667b2228ce96"
    "4d80ce960b167b49110af20f0c399bb2178aaae438d339e02f2d3e892ca35d5e"
    "7a6ddd2c7bd8ee272ab34b452c55859242e301d86b0d6fca36bfcb2118344d2f"
    "283ffd6071a2cf7f6108580f020178d74381cc517d3ed6f7651da8532c742159"
    "0ab755732541216050ed34e70a3b8d455dee6f4f0e039b622d635bdc2a6f3ee6"
    "191916ac3e6e4dec36a8d99831a3c090774187cc66d517225e461eef71ae64f9"
    "61ae064a08f969341e04ea8b249108227406d9fe54c3b5ad3cc555511c45d65f"
    "4665852d1ecdad601e464e370ae6517f1b0b84580463f68a365b73d825c2d9cb"
    "29a417eb0648a8bf30fd66110793873a154b43225e61c2ed3102c6202f6459ce"
    "1ccf0fda68aa9fb960071a5f141097a64f7fb7db3e4d384e06bffb9f312dbe25"
    "4746a28224c3e52b56bec6473b4c7b8179869bd912831c99579151e13feb2007"
    "3150caf975d79f184ad272864c5b4e527a3a96a3002de65e721d281e24dead8e"
    "07758e1e231b8f2f2b7135c91cc0d140017c511d5d73fbe94b242b0f1e4b61f7"
    "451d9ba32c2b456e325bf89d159d527f6b787dbc381af43d47ca10a532be1f3f"
    "5dddd9691d89d7ec6d0a9bc056637543300cf485459beca1164f964a615dbe7f"
    "3b728cba602109d12db80cd235ac225e614eef2f20d634f0598ad0ec68c37d4e"
    "43f1c31f05fc05b605834f8f446d153d626f01a051a77a9e62b87634288d9c43"
    "7ed2bf0c15136fd23d2aefc2694a3dc94d2e631005f4ff671c085d082b0b3d7a"
    "227dd7540a12f8c8016fb2bd528acbda4fade46a18be480834e7895a0b1f7125"
    "79df51d9619f962c41cb93835a2d41090275cb1c1b55647043f0be5745668f3c"
    "20516a2649730ee709d3a47902c16bc61a1a89856c8b1bae2a4e080a19ec4892"
    "019f8a806878f7cc0236865b4fcded906d6cf7341f3ee3637ad82a0b10eace89"
    "2950db2c7c47ddc862749a6479fdbf97140526d1165b24bf041c31bd0de477aa"
    "78fabaeb45e7c4406811b9b37a708608613c29b12b01780b40d61545018e93d7"
    "747486f249aababe034fff9d0f8e0f783635d66c2e9d07a8287a580a38d460ed"
    "1615ff742bb0de6507a14e7e0481f6a94aeec1c9017a7989146bc533743e9df6"
    "7dc1565277df5f986d3b5d8e12c77c230e3a845772578e4b20abf4cd06353f43"
    "383e538c08bdad8101a5c54b197b7c3d34be258d417bdb901a0910152933ac7f"
    "0b25964f1e580fb338c1bbf7415b6cbc4cf5165b613c14027a2fcda9630a16d0"
    "0cecf26701d11b28688b0c7a57dbb431034b95b17cf7d1ad4b195228010cec03"
    "74d631463955afb613d368270211b69d2bac3d02347f5df50846f5e063eb908e"
    "3c3c0b770aebba2c7d660dcc70fa30044c6696bd176f1de1192ddd83578c2c0d"
    "36c72c9452ef987b19e798c902bc43ef332bad7d1316667366c659bf4017a0e5"
    "14e7819b4e51663918f254171832174d4b4838e7630ca73f193f03513f1f6a2d"
    "1d6156f62c126c78413020cb480d94f86091c96d4a7615ac2cf824871dcdd4e4"
    "5461d0d8295e32530ec805e920c7669641cd4f3428f5e26c785393a377947cc8"
    "7ae47be8113a2c6d7a50c0b72e0f2966255192e060161a776f27c94b3a38147c"
    "2f6880b007191e63526b2bc97ab0b8976b25c5a26baa2e1a3acf22c508861b99"
    "18bc9a927bff42905194af91794e64004675583c7e8cd418171b39e51ad62815"
    "28eb066c25e33ece3b9e8fab69b856a04dd9213b34f1224f614dd36848bd9d23"
    "462c4fbc5b9d932077cdc6896b7de19c3cb4ad9766f48fd525b5f5186c1c2e48"
    "6e0dae38782021e266cce6df593373db63ca4ffc209c09a562b98e747c87ea8e"
    "1c9b4c35344d3e0676d54e8f6211a57132da121f0df087747de7cd865ac5198b"
    "32d4c64239855d32447d702b00ade87d6d77808125ca4394486a86a133a3cf3d"
    "0168d7b43f374d2b1f20b1da3d1c854c262bdd0045d5a6f32938b39414398b39"
    "3df6c7d510049a746e6cfe1421c017d231a0a31951258d891d4702614e3cf04e"
    "0573cb8f131c51f0304d95c0374ddeae200dd9642e3463471212f83953e19fa7"
    "67bac079568f6865538e8825553141fb7b5aacf91bf80ec708d410397dc283ae"
    "5b305cf227f4c1133bde08fb015b39f36cc968076516bc8f1694c42c2abf30dd"
    "751a56040500c3414b8048af27bbf91d562650cb68c74a1076f7e96c5b991b5b"
    "7ce49b0027447f2d13e6f9091df174655578e27425f8f14370d2140d3d32a3ee"
    "7b875aa943609d321263e4e977e106a35f58acf91a37f52275a38a513b8808ec"
    "422bb7363081934c3de441df2ff51f3e15974fdc5378060c5ab4501b0bb2a5e0"
    "5879c94d253499ca326d9ffe2e9f19190efce3da2864896b0a3835740ae07fdb"
    "4fa808991d1e2f7e27d1f4402520eb0d431621c217a3094e62538efc3e9d7b6b"
    "5b03a78074b672e6367f820e3b5b537a0fee67092c220d6076e45b6652191f40"
    "5ca4a0ac33c89d45020e3f7e713bf0880740a4515cc38f997ced956960b96d9f"
    "01f728642f5a35680f5887b80ff30c3f58bebed31990bc2c1ad38c1a2866c76c"
    "37aeebaa41a4815b4d87b27a7ac40c6d59478ba92fda4077396288d8344a322a"
    "2490b35d70e10ae76fa685a4337e1b671c031847668ae10a06983aa778a7b8f3"
    "19527f5008a679256ae3a87c219223a2646909bf66d03ee6014c91416661322316"
    "2b744e11a418fa75543f626ee932222b35d5261028cc7c1650fa8e62e3c0d151"
    "cc4dd863d7ac095da8cd3e2b14d98113b1ed80160a5617605e0bac3741a1de06"
    "eb"
)

# Key validation table: 100 entries of (check_value, base_value) as
# packed little-endian uint32 pairs (800 bytes total).
_KEY_TABLE_RAW = bytes.fromhex(
    "c0bc4523640700008e725b711e060000963139500c060000fe7012065c060000"
    "73154e5e4100000049199c7354080000c9acf4021303000063bf893a84010000"
    "5ec00c30f904000045b8d307300900007c55821c1e0300008567a56fbe050000"
    "26df2d7f640700002e79d8273600000077f6040da4000000897b2a22dd030000"
    "07531c2eb70200008faa374c27070000f8df310dc9030000165f0b705a070000"
    "f6951b3f770100002a9c0f30d0080000d40592680b090000dc2e673351060000"
    "26f04935ee040000e0803a2bb603000034ede6260e000000c6688d1939020000"
    "9b3d06216a030000deb6ee5c140700000dbc3c39b70800004ae7555ee3020000"
    "7f209f1284020000b293ae65da00000068add77c27050000e2f5500b04030000"
    "286b61397a0500001d86037ee402000099edf925c10300002f37923a210a0000"
    "1b9ca56c4f0600006123102d9806000075a0ac00e3040000a955a1398b050000"
    "1b6e03080d0200002412be4f28030000ef3ea915280500003d399928da020000"
    "488ba158d2070000e55f1948a7060000b7bf0164b40200000e7c6c113f000000"
    "d3e7ca0e18030000dd9b563f4b04000025b7da40150400002cb3081064050000"
    "1c8bb55fec08000090dc0c417e080000b562b60366020000a3091502d5010000"
    "c13e3e1141080000f9faf94c030600003515e77fc50200001fdd2f4fbe010000"
    "2501db035e0300002ed9012e39040000cc92b36add080000bdeb3f05fd050000"
    "6857de4e8c0800000d50432e9a090000a65a7f3e5d050000ce61393d9d040000"
    "c7d9647b830900005511977ed20700009770f478cd0700004e0dd50a18080000"
    "bf367f52510700000a2d1a311f0a00007e3c624da003000072ecee2a55010000"
    "2e479317db01000080fe1939cd040000de1a5f18d30000009b54c57b45040000"
    "d771f002ba010000d480f67698030000e1a754685200000041b2a45f0a020000"
    "00217632f901000026bed462660200008edee75e0b020000f0409d356c070000"
    "bbd37845410500004161cd034e09000024780167cd010000dd4d18649c070000"
    "5513ad070e0600004d99db001d0600009b368c5bcb04000079a049070c070000"
)
# fmt: on

_KEY_TABLE_COUNT = 100

# Pre-built dict mapping check_value -> base_value for O(1) lookup.
_KEY_TABLE = {
    struct.unpack_from("<I", _KEY_TABLE_RAW, i * 8)[0]: struct.unpack_from(
        "<I", _KEY_TABLE_RAW, i * 8 + 4
    )[0]
    for i in range(_KEY_TABLE_COUNT)
}


class BinaryFileParser:
    """Parser for LTspice Binary File format encrypted files.

    This format uses a two-layer XOR stream cipher:

    1. Each byte is XOR'd with a cyclically repeating 4-byte key derived
       from the ``key2`` header field.
    2. Each byte is further XOR'd with a value from a 2593-byte
       substitution table, indexed by a linear congruential sequence
       ``(base + step * N) mod 2593`` whose *step* is always prime,
       guaranteeing a full-period cycle.
    """

    def __init__(self, file_obj):
        """
        Initialize the parser with a binary-mode file object.

        Args:
            file_obj: File-like object opened in binary mode.
        """
        self.file_obj = file_obj

    @staticmethod
    def check_signature(data):
        """Return ``True`` if *data* starts with the Binary File signature."""
        return len(data) >= 20 and data[:20] == SIGNATURE

    def decrypt_stream(self) -> Generator[bytes, None, tuple[int, int]]:
        """
        Stream-decrypt the file, yielding decrypted chunks.

        Returns:
            Generator that yields decrypted byte chunks.
            The return value (via ``StopIteration``) is a
            ``(crc32, rotate_hash)`` verification tuple.
        """
        # -- Header parsing ------------------------------------------------
        header = self.file_obj.read(28)
        if len(header) < 28:
            raise ValueError("File too short for Binary File header")
        if header[:20] != SIGNATURE:
            raise ValueError("Invalid Binary File signature")

        key1, key2 = struct.unpack_from("<II", header, 20)
        check = key1 ^ key2

        base = _KEY_TABLE.get(check)
        if base is None:
            raise ValueError(
                f"Unrecognized encryption key pair "
                f"(key1=0x{key1:08X}, key2=0x{key2:08X}, check=0x{check:08X})"
            )

        step = _STEP_TABLE[key2 % 26]
        key2_bytes = header[24:28]  # raw LE bytes of key2

        # -- Body decryption -----------------------------------------------
        body = self.file_obj.read()
        if not body:
            return (0, 0)

        n = len(body)

        # Layer 1: cyclic XOR with the 4-byte key2 pattern.
        # Build a repeating key2 mask covering the whole body.
        key2_mask = key2_bytes * (n // 4 + 1)

        # Layer 2: sbox keystream.
        # The index sequence (base + step*i) % modulus has period exactly
        # `modulus` (2593) because `step` is always coprime to 2593.
        # Compute one full cycle, then tile to cover the body length.
        sbox = _SBOX
        modulus = _SBOX_MODULUS
        one_cycle = bytes(sbox[(base + step * i) % modulus] for i in range(modulus))
        full, remainder = divmod(n, modulus)
        sbox_stream = one_cycle * full + one_cycle[:remainder]

        # Apply both XOR layers in bulk using integer arithmetic.
        body_int = int.from_bytes(body, "big")
        key2_int = int.from_bytes(key2_mask[:n], "big")
        sbox_int = int.from_bytes(sbox_stream, "big")
        decrypted = (body_int ^ key2_int ^ sbox_int).to_bytes(n, "big")

        # -- Verification checksums ----------------------------------------
        crc = binascii.crc32(decrypted)

        # Compute a rotate-left hash over every byte.  Inlining _rol32
        # and grouping by rotation amount (which cycles every 32 bytes)
        # avoids per-byte function-call overhead.
        rotate_hash = 0
        mask = _MASK32
        for i, byte_val in enumerate(decrypted):
            shift = (i + 1) & 31
            if shift:
                rotated = ((byte_val << shift) | (byte_val >> (32 - shift))) & mask
                rotate_hash = (rotate_hash + rotated) & mask
            else:
                rotate_hash = (rotate_hash + byte_val) & mask

        yield decrypted
        return (crc, rotate_hash)
