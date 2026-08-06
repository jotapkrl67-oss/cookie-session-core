from __future__ import annotations

import logging

from cookie_session_core.diagnostic_logging import configure_diagnostic_logging
from cookie_session_core.redaction import redact


def test_redaction_covers_urls_json_and_headers():
    raw = (
        'database=postgresql://admin:supersecret@db.example/core '
        'url=https://example.com/login?token=secret '
        'Authorization: Bearer jwt-value '
        'payload={"password":"hunter2","api_key":"key-value"}'
    )

    cleaned = redact(raw)

    assert "supersecret" not in cleaned
    assert "jwt-value" not in cleaned
    assert "hunter2" not in cleaned
    assert "key-value" not in cleaned
    assert "token=secret" not in cleaned
    assert cleaned.count("[REDACTED]") >= 5


def test_rotating_txt_logger_writes_traceback_and_redacts_secrets(tmp_path):
    target = tmp_path / "diagnostics.txt"
    configure_diagnostic_logging(
        file_path=str(target),
        level="INFO",
        max_bytes=1_000_000,
        backup_count=2,
    )
    logger = logging.getLogger("cookie_session_core.test_diagnostics")

    try:
        raise RuntimeError("Authorization: Bearer do-not-write-me")
    except RuntimeError:
        logger.exception("login_crashed password=hunter2")

    for selected_logger in (
        logging.getLogger("cookie_session_core"),
        logging.getLogger(),
    ):
        for handler in selected_logger.handlers:
            handler.flush()
    contents = target.read_text(encoding="utf-8")

    assert "login_crashed" in contents
    assert "Traceback" in contents
    assert "RuntimeError" in contents
    assert "do-not-write-me" not in contents
    assert "hunter2" not in contents
    assert "[REDACTED]" in contents
