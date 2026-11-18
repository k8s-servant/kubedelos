"""The name of the person using the UI, taken from a trusted proxy header and cleaned before it is stored or shown.

The value is attacker-influenced text (a header), so control and format characters are removed (no header or log
injection, no line breaks, no hidden bidi marks) and its length is capped.
"""

import unicodedata

from fastapi import Request

MAX_IDENTITY = 256
# Control, format, and line and paragraph separator characters.
STRIPPED = ("Cc", "Cf", "Zl", "Zp")


def clean_identity(raw: str | None) -> str | None:
    """``raw`` without control, format and line separator characters, trimmed and cut to ``MAX_IDENTITY``; ``None`` if empty."""
    if raw is None:
        return None
    kept = "".join(char for char in raw if unicodedata.category(char) not in STRIPPED)
    return kept.strip()[:MAX_IDENTITY] or None


def identity(request: Request) -> str | None:
    """The signed-in name the serve middleware put on the request, or ``None``."""
    return getattr(request.state, "identity", None)
