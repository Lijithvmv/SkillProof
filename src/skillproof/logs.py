"""Structured logs: one JSON object per line on stdout, for any log collector.

Every API request is logged with a request id (taken from an incoming `X-Request-ID` or generated, and returned in the
response), method, path, status, duration, tenant and actor. Background work (evaluation jobs, alert delivery,
backups) logs what it did with the same shape. Skill contents, tokens and secrets are never logged.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

LOGGER_NAME = "skillproof"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {"time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
                 "level": record.levelname.lower(), "event": record.getMessage()}
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["error"] = self.formatException(record.exc_info)[-2000:]
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure(level: str | None = None) -> None:
    """JSON lines on stdout at SKILLPROOF_LOG_LEVEL (default info). Called once when the service starts."""
    logger = logging.getLogger(LOGGER_NAME)
    if not any(getattr(h, "_skillproof", False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        handler._skillproof = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    from skillproof.config import settings

    logger.setLevel((level or settings().log_level).upper())
    logger.propagate = False


def log(event: str, level: int = logging.INFO, /, **fields: object) -> None:
    # level is positional-only, so a logged field called `level` can never replace it
    logging.getLogger(LOGGER_NAME).log(level, event, extra={"fields": fields})
