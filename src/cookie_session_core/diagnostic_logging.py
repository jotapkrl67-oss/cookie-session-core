from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import warnings
from pathlib import Path
from typing import TextIO

from .redaction import SecretRedactionFilter, redact


class RedactingFormatter(logging.Formatter):
    """Redact the complete rendered record, including exception tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return str(redact(super().format(record)))


class DiagnosticRecordFilter(SecretRedactionFilter):
    """Keep package INFO records plus WARNING+ failures from dependencies."""

    def filter(self, record: logging.LogRecord) -> bool:
        super().filter(record)
        return record.name.startswith("cookie_session_core") or record.levelno >= logging.WARNING


def _formatter() -> RedactingFormatter:
    return RedactingFormatter(
        fmt="%(asctime)sZ level=%(levelname)s logger=%(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _handler_exists(logger: logging.Logger, marker: str) -> bool:
    return any(getattr(handler, "_cookie_core_handler", None) == marker for handler in logger.handlers)


def _mark(handler: logging.Handler, marker: str) -> logging.Handler:
    handler._cookie_core_handler = marker  # type: ignore[attr-defined]
    handler.addFilter(SecretRedactionFilter())
    handler.setFormatter(_formatter())
    return handler


def configure_diagnostic_logging(
    *,
    file_path: str,
    level: str = "INFO",
    max_bytes: int = 20_000_000,
    backup_count: int = 5,
    stream: TextIO | None = None,
) -> Path | None:
    """Configure stderr plus a bounded UTF-8 diagnostic file.

    File creation failure is intentionally non-fatal: diagnostics remain on
    stderr so a bad volume mount never prevents the application from starting.
    """

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    package_logger = logging.getLogger("cookie_session_core")
    package_logger.setLevel(numeric_level)
    package_logger.propagate = True

    if not _handler_exists(package_logger, "stderr"):
        stderr_handler = _mark(logging.StreamHandler(stream or sys.stderr), "stderr")
        stderr_handler.setLevel(numeric_level)
        package_logger.addHandler(stderr_handler)

    resolved_path: Path | None = None
    if file_path.strip():
        target = Path(os.path.expandvars(file_path)).expanduser().resolve()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                target,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
                delay=True,
            )
            file_handler = _mark(file_handler, f"file:{target}")
            file_handler.filters.clear()
            file_handler.addFilter(DiagnosticRecordFilter())
            file_handler.setLevel(numeric_level)
            root = logging.getLogger()
            if not _handler_exists(root, f"file:{target}"):
                root.addHandler(file_handler)
                uvicorn_error = logging.getLogger("uvicorn.error")
                if not uvicorn_error.propagate and not _handler_exists(
                    uvicorn_error, f"file:{target}"
                ):
                    uvicorn_error.addHandler(file_handler)
            else:
                file_handler.close()
            resolved_path = target
        except (OSError, ValueError) as exc:
            package_logger.error(
                "diagnostic_log_file_unavailable path=%s error=%s",
                target,
                type(exc).__name__,
            )

    logging.captureWarnings(True)
    warnings.simplefilter("default")
    package_logger.info(
        "diagnostic_logging_ready file=%s level=%s max_bytes=%s backups=%s",
        resolved_path or "stderr-only",
        logging.getLevelName(numeric_level),
        max_bytes,
        backup_count,
    )
    return resolved_path
