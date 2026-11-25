"""Structured JSON logging configuration for AgentShield."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Optional

from app.database import insert_application_log


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class JsonLogFormatter(logging.Formatter):
    """Format Python log records as single-line structured JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        # Never interpolate record.msg as a format string when args are absent.
        raw_message = record.getMessage()
        payload = {
            "timestamp": utc_now_iso(),
            "severity": record.levelname,
            "component": getattr(record, "component", record.name),
            "message": str(raw_message),
            "incident_id": getattr(record, "incident_id", None),
        }
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the root AgentShield structured JSON logger."""
    logger = logging.getLogger("agentshield")
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)

    return logger


_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def record_structured_log(
    db_path: Path | str,
    severity: str,
    component: str,
    message: str,
    incident_id: Optional[str] = None,
) -> None:
    """Emit a structured JSON log and persist it inertly to SQLite.

    Passes ``"%s", message`` to ``logger.log`` so untrusted payloads containing
    format specifiers or template tokens are never evaluated as format strings.
    """
    normalized_severity = severity.upper()
    if normalized_severity not in _LEVEL_MAP:
        normalized_severity = "INFO"

    logger = logging.getLogger("agentshield")
    if not logger.handlers:
        configure_logging()

    timestamp = utc_now_iso()
    logger.log(
        _LEVEL_MAP[normalized_severity],
        "%s",
        message,
        extra={
            "component": component,
            "incident_id": incident_id,
        },
    )

    insert_application_log(
        db_path=db_path,
        timestamp=timestamp,
        severity=normalized_severity,
        component=component,
        message=message,
        incident_id=incident_id,
    )
