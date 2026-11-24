"""PII detection and masking (PDR 6.3.1, 6.6).

Regex backend is the offline default. When Presidio is installed and selected,
its analyser is used as an additional detector; the regex layer stays on as a
backstop so the system never silently loses coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"(?<!\w)(?:\+\d{1,3}[\s-]?)?(?:\(?\d{3}\)?[\s-]?)\d{3}[\s-]?\d{4}(?!\w)"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    "ssn_like": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "customer_id": re.compile(r"\b(?:CUST|INV|PK)-\d{3,6}\b"),
}

_presidio = None


def _get_presidio():
    global _presidio
    if _presidio is None:
        try:
            from presidio_analyzer import AnalyzerEngine

            _presidio = AnalyzerEngine()
        except Exception:
            _presidio = False
    return _presidio


@dataclass
class PiiHit:
    field_type: str
    value: str
    start: int
    end: int


def detect(text: str, backend: str = "regex", types: list[str] | None = None) -> list[PiiHit]:
    enabled = types or list(PATTERNS)
    hits: list[PiiHit] = []
    for field_type in enabled:
        pattern = PATTERNS.get(field_type)
        if not pattern:
            continue
        for m in pattern.finditer(text):
            hits.append(PiiHit(field_type, m.group(0), m.start(), m.end()))
    if backend == "presidio":
        engine = _get_presidio()
        if engine:
            try:
                results = engine.analyze(text=text, language="en")
                for r in results:
                    if r.entity_type in {"EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "US_SSN", "PERSON"}:
                        hits.append(PiiHit(r.entity_type, text[r.start : r.end], r.start, r.end))
            except Exception:
                pass
    return sorted(hits, key=lambda h: (h.start, h.end))


def mask(text: str, backend: str = "regex", mask_char: str = "*", types: list[str] | None = None) -> tuple[str, list[str]]:
    """Return (masked_text, detected_field_types)."""
    hits = detect(text, backend=backend, types=types)
    if not hits:
        return text, []
    # De-duplicate overlapping spans, keeping the longest at each position.
    ordered = sorted(hits, key=lambda h: (-(h.end - h.start), h.start))
    kept: list[PiiHit] = []
    for h in ordered:
        if any(not (h.end <= k.start or h.start >= k.end) for k in kept):
            continue
        kept.append(h)
    kept.sort(key=lambda h: h.start)
    out = []
    pos = 0
    found: list[str] = []
    for h in kept:
        out.append(text[pos : h.start])
        out.append(mask_char * len(h.value))
        found.append(h.field_type)
        pos = h.end
    out.append(text[pos:])
    return "".join(out), found


def contains_pii(text: str, backend: str = "regex", types: list[str] | None = None) -> bool:
    return bool(detect(text, backend=backend, types=types))
