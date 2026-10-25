"""Generalizing delivered field names to the dictionary's `[*]` array-index notation."""

from __future__ import annotations

import re

_BRACKET_INDEX = re.compile(r"\[\d+\]")


def generic_field_name(name: str) -> str:
    """Collapse concrete array indices in a delivered field name to `[*]`.

    Handles both dotted (`powerCurve.3.soc`) and bracketed (`powerCurve[3].soc`,
    `powerCurve.[3].soc`) index notation, so a dictionary-style name with literal `[*]`
    segments and a delivered name with concrete indices normalize to the same string.

    Args:
        name: a delivered field name, with concrete indices or none at all.

    Returns:
        The same name with every array index replaced by `[*]`.
    """
    text = _BRACKET_INDEX.sub(".[*]", name).replace("..[*]", ".[*]")
    return ".".join("[*]" if part.isdigit() else part for part in text.split("."))
