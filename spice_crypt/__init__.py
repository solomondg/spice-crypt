# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
SpiceCrypt - A library for decrypting LTspice® and PSpice® encrypted files
"""

from importlib.metadata import version

from spice_crypt.decrypt import decrypt, decrypt_stream
from spice_crypt.ltspice.binary_file import BinaryFileParser
from spice_crypt.ltspice.crypto_state import CryptoState
from spice_crypt.ltspice.decrypt import LTspiceFileParser
from spice_crypt.ltspice.des import LTspiceDES
from spice_crypt.pspice.decrypt import PSpiceFileParser
from spice_crypt.pspice.des import PSpiceDES

__version__ = version("spice-crypt")

__all__ = [
    "BinaryFileParser",
    "CryptoState",
    "LTspiceDES",
    "LTspiceFileParser",
    "PSpiceDES",
    "PSpiceFileParser",
    "decrypt",
    "decrypt_stream",
]
