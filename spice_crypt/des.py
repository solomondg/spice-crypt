# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backward-compatibility shim — imports moved to :mod:`spice_crypt.ltspice.des`."""

from spice_crypt._constants import MASK32 as _MASK32
from spice_crypt._constants import MASK64 as _MASK64
from spice_crypt.ltspice.des import LTspiceDES

__all__ = ["_MASK32", "_MASK64", "LTspiceDES"]
