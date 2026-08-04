from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class UpstreamClassification(str, Enum):
    NOT_BLOCKED = "not_blocked"
    CLOUDFLARE_CHALLENGE = "cloudflare_challenge"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_FORBIDDEN = "upstream_forbidden"
    TRANSIENT_UPSTREAM_FAILURE = "transient_upstream_failure"
    UNKNOWN_BLOCK = "unknown_block"


@dataclass(frozen=True)
class ClassificationResult:
    classification: UpstreamClassification
    body_inspected_bytes: int = 0


_CHALLENGE_MARKERS = (
    b"_cf_chl_opt",
    b"cdn-cgi/challenge-platform",
    b"cf-turnstile",
    b"_cf_chl_form",
    b"challenge-form",
    b"just a moment...",
)
_TRANSIENT_MARKERS = re.compile(
    rb"(?:temporarily unavailable|bad gateway|gateway timeout|origin is unreachable)", re.I
)


def _header(headers: Any, name: str) -> str:
    getter = getattr(headers, "get", None)
    return str(getter(name, "") or "") if callable(getter) else ""


def has_cloudflare_headers(headers: Any) -> bool:
    if "cloudflare" in _header(headers, "server").lower():
        return True
    items = getattr(headers, "items", None)
    return bool(callable(items) and any(str(key).lower().startswith("cf-") for key, _ in items()))


def _inspection_body(body: bytes | None, headers: Any, limit: int) -> bytes:
    if not body or limit <= 0:
        return b""
    sample = bytes(body[: limit + 1])
    if len(sample) > limit:
        sample = sample[:limit]
    if _header(headers, "content-encoding").lower().strip() == "gzip":
        try:
            sample = gzip.decompress(sample)
        except (EOFError, OSError):
            return b""
        sample = sample[:limit]
    return sample.lower()


def classify_upstream_response(
    status: int,
    headers: Any,
    body: bytes | None = None,
    *,
    inspection_limit_bytes: int = 262_144,
) -> ClassificationResult:
    """Classify a bounded response sample without changing the original body."""
    sample = _inspection_body(body, headers, inspection_limit_bytes)
    inspected = len(sample)
    if status == 429:
        return ClassificationResult(UpstreamClassification.RATE_LIMITED, inspected)

    mitigated = _header(headers, "cf-mitigated").lower() == "challenge"
    marker = any(item in sample for item in _CHALLENGE_MARKERS)
    cf_headers = has_cloudflare_headers(headers)
    if mitigated or (status in {403, 503} and marker and cf_headers):
        return ClassificationResult(UpstreamClassification.CLOUDFLARE_CHALLENGE, inspected)
    if status == 403:
        classification = (
            UpstreamClassification.UNKNOWN_BLOCK
            if cf_headers
            else UpstreamClassification.UPSTREAM_FORBIDDEN
        )
        return ClassificationResult(classification, inspected)
    if status in {502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527}:
        return ClassificationResult(UpstreamClassification.TRANSIENT_UPSTREAM_FAILURE, inspected)
    if status >= 400 and (_TRANSIENT_MARKERS.search(sample) or marker):
        return ClassificationResult(UpstreamClassification.UNKNOWN_BLOCK, inspected)
    return ClassificationResult(UpstreamClassification.NOT_BLOCKED, inspected)
