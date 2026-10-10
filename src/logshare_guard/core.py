"""Conservative redaction of explicitly supported fields in JSON data.

This module does not detect secrets embedded in arbitrary prose, file contents,
or undocumented encodings. It makes no network requests.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

DEFAULT_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "api_secret",
    "x_api_key",
    "x_auth_token",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "session_id",
    "private_key",
    "csrf_token",
    "x_csrf_token",
)

_HTTP_CANDIDATE = re.compile(r"^https?:", re.IGNORECASE)
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


def _normalize_key(key: str) -> str:
    """Ignore case and punctuation when matching explicitly listed keys."""
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def redact(
    value: Any, extra_keys: Iterable[str] = ()
) -> tuple[Any, dict[str, int]]:
    """Return a new JSON value and counts grouped by fixed redaction rules.

    Sensitive fields are replaced in their entirety, including object or array
    values. Objects with a sensitive ``name`` and a ``value`` field retain the
    name and redact the value. Matching casefolds keys, then keeps only ASCII
    letters and digits. Additional keys follow the same matching rules.

    HTTP(S) URL strings lose user information, sensitive query values, and any
    fragment. Malformed URL candidates are replaced in their entirety. Query
    markers are percent-encoded. Ordinary free text is passed through.

    The input is never modified. Counts contain no input keys, paths, or values.
    A replaced field counts once even if its original value contains many items.
    """
    if isinstance(extra_keys, str):
        raise TypeError("extra_keys must be an iterable of key names, not a string")
    sensitive_keys = {_normalize_key(key) for key in DEFAULT_SENSITIVE_KEYS}
    for key in extra_keys:
        if not isinstance(key, str):
            raise TypeError("extra_keys must contain only strings")
        normalized = _normalize_key(key)
        if normalized:
            sensitive_keys.add(normalized)

    counts: Counter[str] = Counter()

    def replace(rule: str) -> str:
        counts[rule] += 1
        return REDACTED

    def redact_url(original: str) -> str:
        candidate = original.strip()
        if not _HTTP_CANDIDATE.match(candidate):
            return original

        try:
            # urlsplit silently strips certain control characters; reject them
            # first so parser cleanup cannot conceal a malformed candidate.
            if any(ord(char) < 32 or ord(char) == 127 for char in original):
                raise ValueError
            if any(char.isspace() for char in candidate):
                raise ValueError
            if "\\" in candidate or _INVALID_PERCENT.search(candidate):
                raise ValueError

            parts = urlsplit(candidate)
            if parts.scheme.casefold() not in {"http", "https"}:
                raise ValueError
            if not parts.netloc or not parts.hostname:
                raise ValueError
            # Accessing port validates both numeric syntax and the valid range.
            _ = parts.port

            url_counts: Counter[str] = Counter()
            netloc = parts.netloc
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[1]
                url_counts["url_userinfo"] += 1

            # Preserve the spelling of unrelated query parameters. Recognize
            # semicolon separators conservatively as well as ampersands.
            query_parts = re.split(r"([&;])", parts.query)
            for index in range(0, len(query_parts), 2):
                raw_key, _, _raw_value = query_parts[index].partition("=")
                key = unquote_plus(raw_key, errors="strict")
                if _normalize_key(key) in sensitive_keys:
                    query_parts[index] = f"{raw_key}={quote(REDACTED, safe='')}"
                    url_counts["url_query"] += 1

            fragment = parts.fragment
            if "#" in candidate:
                fragment = REDACTED
                url_counts["url_fragment"] += 1

            result = urlunsplit(
                (parts.scheme, netloc, parts.path, "".join(query_parts), fragment)
            )
        except (ValueError, UnicodeError):
            return replace("invalid_url")

        counts.update(url_counts)
        return result if url_counts else original

    def visit(item: Any) -> Any:
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise TypeError("JSON object keys must be strings")
            has_sensitive_name = any(
                _normalize_key(key) == "name"
                and isinstance(child, str)
                and _normalize_key(child) in sensitive_keys
                for key, child in item.items()
            )
            result: dict[str, Any] = {}
            for key, child in item.items():
                normalized = _normalize_key(key)
                if normalized in sensitive_keys:
                    result[key] = replace("sensitive_key")
                elif normalized == "value" and has_sensitive_name:
                    result[key] = replace("named_value")
                else:
                    result[key] = visit(child)
            return result
        if isinstance(item, list):
            return [visit(child) for child in item]
        if isinstance(item, str):
            return redact_url(item)
        if item is None or isinstance(item, (bool, int, float)):
            return item
        raise TypeError("value must contain only JSON-compatible types")

    result = visit(value)
    return result, dict(counts)
