"""Test-only comparison: contiguous printable bytes without stack interpretation."""

from __future__ import annotations

import re


def visible_literals(data: bytes) -> set[str]:
    return {item[:-1].decode("ascii") for item in re.findall(rb"[ -~]{4,64}\x00", data)
            if item.startswith(b"SAFE_")}
