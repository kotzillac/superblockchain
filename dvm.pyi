# SPDX-License-Identifier: GPL-3.0-or-later
from collections.abc import Callable

def execute(code: bytes, gas: int, systemcall: Callable[[int, int, int, int, bytes], tuple[bytes | None, int]]) -> tuple[int | None, int]: ...