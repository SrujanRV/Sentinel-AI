"""Log sanitizer: normalize -> detect injection -> redact.

ALL log content is UNTRUSTED DATA.  Every event field must pass through
sanitize() before reaching any LLM call.

Processing order (important):
    1. Unicode NFKC normalisation + zero-width / control-char removal.
       Defeats homoglyph and invisible-char obfuscation.
    2. Injection-heuristic detection on the clean, pre-redaction text.
       Running this before redaction ensures key=value patterns can't
       hide injection payloads in their values.
    3. Sequential redaction: typed placeholders replace PII / secrets.
"""

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field

# ══ Result type ═══════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class SanitizeResult:
    """Immutable outcome of sanitizing one piece of text."""

    text: str
    redaction_counts: dict[str, int] = field(default_factory=dict)
    injection_flagged: bool = False
    matched_rules: list[str] = field(default_factory=list)


# ══ Step 1: normalisation ══════════════════════════════════════════════════════

# Zero-width and invisible Unicode chars commonly used to obfuscate payloads.
_ZERO_WIDTH = re.compile(
    "["
    "\u200b\u200c\u200d\u200e\u200f"  # zero-width space / joiners / marks
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embedding / override
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner / invisible math ops
    "\ufeff"                           # BOM / zero-width no-break space
    "\u00ad"                           # soft hyphen
    "]"
)
# Non-printable control characters (keep \t \r \n - they become spaces below).
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WHITESPACE = re.compile(r"[ \t\r\n]+")


def _normalize(text: str) -> str:
    """NFKC -> strip zero-width/control chars -> collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)  # collapses fullwidth/compat forms
    text = _ZERO_WIDTH.sub("", text)
    text = _CONTROL.sub("", text)
    return _WHITESPACE.sub(" ", text).strip()


# ══ Step 2: injection detection ════════════════════════════════════════════════

# Each entry: (compiled_pattern, rule_name).
_INJECTION_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|above|prior|the\s+above)\s+"
            r"(?:instructions?|commands?|prompts?|context|rules?)",
            re.IGNORECASE,
        ),
        "ignore_previous_instructions",
    ),
    (
        re.compile(
            r"\b(?:"
            r"you\s+are\s+now\b"
            r"|act\s+as\s+(?:a|an)\s+\w"
            r"|pretend\s+to\s+be\b"
            r"|forget\s+(?:you\s+are|that\s+you)\b"
            r"|roleplay\s+as\b"
            r"|your\s+new\s+(?:role|persona|instructions?)\b"
            r")",
            re.IGNORECASE,
        ),
        "role_hijack",
    ),
    (
        re.compile(
            r"<\s*/?(?:system|assistant|human|user|ai|gpt|claude)\s*>",
            re.IGNORECASE,
        ),
        "fake_system_tag",
    ),
    (
        re.compile(
            r"\[\s*(?:system|assistant|ai|gpt|claude|gemini)\s*\]",
            re.IGNORECASE,
        ),
        "fake_bracket_tag",
    ),
    (
        re.compile(
            r"(?:reveal|show|print|display|repeat|expose|tell\s+me)\s+"
            r"(?:me\s+)?(?:your\s+)?(?:system\s+)?"
            r"(?:prompt|instructions?|context|rules?|guidelines?)",
            re.IGNORECASE,
        ),
        "reveal_prompt",
    ),
    # DAN is case-sensitive (all-caps acronym) to reduce false positives.
    (re.compile(r"\bDAN\b"), "jailbreak_DAN"),
    (re.compile(r"\bjailbreak\b", re.IGNORECASE), "jailbreak_keyword"),
    (
        re.compile(
            r'"(?:tool_call|function_call|name)"\s*:\s*"[^"]*"',
            re.IGNORECASE,
        ),
        "structured_tool_injection",
    ),
]


def _detect_injection(text: str) -> tuple[bool, list[str]]:
    """Return (flagged, deduplicated list of matched rule names)."""
    matched: list[str] = []
    for pattern, rule_name in _INJECTION_RULES:
        if pattern.search(text) and rule_name not in matched:
            matched.append(rule_name)
    return bool(matched), matched


# ══ Step 3: redaction ══════════════════════════════════════════════════════════


def _luhn_valid(raw: str) -> bool:
    """Return True iff the digit sequence in *raw* satisfies the Luhn check."""
    digits = [int(c) for c in raw if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _kv_replacer(m: re.Match[str]) -> str:
    """Keep the key name; replace only the secret value."""
    full = m.group(0)
    sep = re.search(r"\s*[=:]\s*", full)
    return (full[: sep.end()] + "[REDACTED_SECRET]") if sep else "[REDACTED_SECRET]"


def _card_replacer(m: re.Match[str]) -> str:
    """Redact only when the digit sequence passes the Luhn algorithm."""
    raw = m.group(0)
    return "[REDACTED_CARD]" if _luhn_valid(raw) else raw


# Type alias for a redaction replacement: either a fixed string or a callable.
_Replacer = str | Callable[[re.Match[str]], str]

# Ordered list of (label, pattern, replacement).
# More-specific / higher-risk patterns come first.
_REDACT_RULES: list[tuple[str, re.Pattern[str], _Replacer]] = [
    # AWS IAM access keys (AKIA / ASIA / ABIA / ACCA prefix).
    (
        "aws_key",
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    # Bearer tokens BEFORE standalone JWTs so the whole header value is caught.
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),
        "[REDACTED_BEARER_TOKEN]",
    ),
    # Standalone JWTs (eyJ... three-part base64url).
    (
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
        "[REDACTED_JWT]",
    ),
    # Email addresses (IPs and usernames are intentionally NOT redacted).
    (
        "email",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "[REDACTED_EMAIL]",
    ),
    # key=value or key: value where key is a known secret keyword.
    (
        "secret",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|token|api_key|apikey|api[-_]key"
            r"|secret(?:_key)?|auth(?:orization)?)\s*[=:]\s*\S+"
        ),
        _kv_replacer,
    ),
    # Credit / debit card numbers (13-19 digits, optional spaces/dashes between).
    # Luhn check cuts false positives significantly.
    (
        "card",
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        _card_replacer,
    ),
    # Phone numbers: international (+1-555-…) and US ((555) 555-5555) formats.
    # Dots used as separators in IPs prevent false matches on IPv4 addresses.
    (
        "phone",
        re.compile(
            r"(?<!\d)"
            r"(?:"
            r"\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}"
            r"|\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}"
            r")"
            r"(?!\d)"
        ),
        "[REDACTED_PHONE]",
    ),
]


def _make_counting_replacer(
    fn: Callable[[re.Match[str]], str],
    count: list[int],
) -> Callable[[re.Match[str]], str]:
    """Wrap *fn* to increment *count[0]* when a substitution actually occurs."""

    def _replacer(m: re.Match[str]) -> str:
        result = fn(m)
        if result != m.group(0):
            count[0] += 1
        return result

    return _replacer


def _apply_redactions(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for label, pattern, replacement in _REDACT_RULES:
        if callable(replacement):
            count: list[int] = [0]
            text = pattern.sub(_make_counting_replacer(replacement, count), text)
            if count[0]:
                counts[label] = count[0]
        else:
            text, n = pattern.subn(replacement, text)
            if n:
                counts[label] = n
    return text, counts


# ══ Public API ═════════════════════════════════════════════════════════════════


def sanitize(text: str) -> SanitizeResult:
    """Normalize, detect prompt injection, and redact PII / secrets.

    Args:
        text: Raw, untrusted field value (e.g. a log message).

    Returns:
        SanitizeResult whose ``.text`` is safe to pass to an LLM.
        Secrets are replaced with typed ``[REDACTED_*]`` placeholders.
        ``injection_flagged`` is True if any heuristic matched.
    """
    text = _normalize(text)
    flagged, rules = _detect_injection(text)
    text, counts = _apply_redactions(text)
    return SanitizeResult(
        text=text,
        redaction_counts=counts,
        injection_flagged=flagged,
        matched_rules=rules,
    )
