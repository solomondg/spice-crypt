# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
SpiceCrypt - A library for decrypting LTSpice encrypted files
"""

__version__ = "1.0.0"

from spice_crypt.crypto_state import CryptoState
from spice_crypt.decrypt import LTSpiceFileParser, decrypt, decrypt_stream
from spice_crypt.des import LTSpiceDES

__all__ = ["CryptoState", "LTSpiceDES", "LTSpiceFileParser", "decrypt", "decrypt_stream"]
