# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backward-compatibility shim — imports moved to :mod:`spice_crypt.ltspice.crypto_state`.

.. deprecated:: 2.0.0
    Import from :mod:`spice_crypt.ltspice.crypto_state` instead.
"""

import warnings

from spice_crypt.ltspice.crypto_state import CryptoState

warnings.warn(
    "spice_crypt.crypto_state is deprecated, use spice_crypt.ltspice.crypto_state instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["CryptoState"]
