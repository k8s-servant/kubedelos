"""The name of the person using the UI, taken from a trusted proxy header and cleaned before it is stored or shown.

The value is attacker-influenced text (a header), so control and format characters are removed (no header or log
injection, no hidden bidi marks) and its length is capped.
"""

import unicodedata

from fastapi import Request

MAX_IDENTITY = 256


def clean_identity(raw: str | None) -> str | None:
    """``raw`` without control and format characters, trimmed and cut to ``MAX_IDENTITY``; ``None`` if empty."""
    if raw is None:
        return None
    kept = "".join(char for char in raw if unicodedata.category(char) not in ("Cc", "Cf"))
    return kept.strip()[:MAX_IDENTITY] or None


def identity(request: Request) -> str | None:
    """The signed-in name the serve middleware put on the request, or ``None``."""
    return getattr(request.state, "identity", None)
