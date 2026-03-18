# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backward-compatibility shim — imports moved to :mod:`spice_crypt.ltspice.binary_file`."""

from spice_crypt.ltspice.binary_file import SIGNATURE, BinaryFileParser

__all__ = ["SIGNATURE", "BinaryFileParser"]
