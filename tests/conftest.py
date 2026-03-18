# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared test helpers and constants."""

from __future__ import annotations

PLAINTEXT_BODY = ".subckt TEST_RES 1 2\nR1 1 2 1k\n.ends TEST_RES\n"


def extract_body(decrypted: str) -> str:
    """Extract the subcircuit body (.subckt through .ends) from decrypted output."""
    lines = decrypted.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.strip().startswith(".subckt"))
    end = next(i for i, line in enumerate(lines) if line.strip().startswith(".ends"))
    return "".join(lines[start : end + 1])
