from __future__ import annotations

import logging
import re
from typing import Any

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+"),
    re.compile(r"(?i)(cf_clearance=)[^;\s]+"),
    re.compile(r"(?i)((?:token|grant|password|api[_-]?key)=)[^&\s]+"),
    re.compile(
        r'''(?i)(["'](?:authorization|cookie|set-cookie|token|grant|password|'''
        r'''api[_-]?key|secret)["']\s*:\s*["'])[^"']+'''
    ),
)
_URL_QUERY = re.compile(r"(https?://[^\s?]+)\?[^\s]+", re.I)
_URL_CREDENTIALS = re.compile(r"(?i)(\b(?:postgres(?:ql)?|https?)://)[^/@\s]+@")


def redact(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    output = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    output = _URL_QUERY.sub(r"\1?[REDACTED]", output)
    for pattern in _SECRET_PATTERNS:
        output = pattern.sub(r"\1[REDACTED]", output)
    return output


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact(item) for item in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: redact(value) for key, value in record.args.items()}
        return True


def install_redaction(logger: logging.Logger) -> None:
    if not any(isinstance(item, SecretRedactionFilter) for item in logger.filters):
        logger.addFilter(SecretRedactionFilter())
