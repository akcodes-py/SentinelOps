"""Bounded input normalisation (PDR 6.3.8).

Cheap checks run before this module; decoding is depth- and size-bounded so it
cannot be used to exhaust the gateway.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_SPLIT_WORD = re.compile(r"\b(?:[a-zA-Z]\s+){3,}[a-zA-Z]\b")
_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


@dataclass
class Normalised:
    text: str
    decoded_layers: int = 0
    truncated: bool = False


def normalise(text: str, max_depth: int = 3, max_expansion: int = 4, max_chars: int = 4000) -> Normalised:
    """Normalise unicode, split words and a bounded number of base64 layers."""
    original_len = len(text)
    out = unicodedata.normalize("NFKC", text)

    # Rejoin split words such as "i g n o r e   a l l".
    def join(m: re.Match[str]) -> str:
        return m.group(0).replace(" ", "")

    out = _SPLIT_WORD.sub(join, out)

    depth = 0
    while depth < max_depth:
        matches = [m for m in _B64.finditer(out) if len(m.group(0)) <= max_chars]
        if not matches:
            break
        decoded_any = False
        for m in matches:
            token = m.group(0)
            try:
                raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
                decoded = raw.decode("utf-8", errors="strict")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if not decoded.isprintable() or len(decoded) > max_chars:
                continue
            out = out.replace(token, decoded)
            decoded_any = True
            depth += 1
            break
        if not decoded_any:
            break
        if len(out) > original_len * max_expansion:
            break

    truncated = len(out) > max_chars
    if truncated:
        # Scan both ends so padding cannot hide a payload.
        out = out[:max_chars] + " " + out[-max_chars:]
    return Normalised(text=out, decoded_layers=depth, truncated=truncated)
