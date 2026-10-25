"""Logging configuration: structlog on top of stdlib logging.

Routing stdlib logging through structlog's formatter means log records from
third-party libraries (e.g. `requests`, `httpx`) get the same console/JSON
rendering as Carchive's own structlog loggers, instead of a second,
differently formatted stream.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from carchive.core.redact import redact, redact_csrf_token


def _redact_recursive(value: Any) -> Any:
    """Apply `redact`/`redact_csrf_token` to every string reachable from `value`."""
    if isinstance(value, str):
        return redact_csrf_token(redact(value))
    if isinstance(value, dict):
        return {key: _redact_recursive(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_recursive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_recursive(item) for item in value)
    return value


def _redact_event(
    logger: object, method_name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Structlog processor that redacts secrets and VINs from the whole event dict."""
    return dict(_redact_recursive(dict(event_dict)))


def configure_logging(verbose: bool, fmt: str) -> None:
    """Configure stdlib logging and structlog for the whole process.

    Args:
        verbose: if True, the root logger level is DEBUG, else INFO.
        fmt: one of "console", "json" or "auto". "auto" picks "console" when
            stderr is a TTY and "json" otherwise.

    Raises:
        ValueError: if `fmt` is not one of the accepted values.
    """
    if fmt == "auto":
        fmt = "console" if sys.stderr.isatty() else "json"
    if fmt not in ("console", "json"):
        raise ValueError(f"unknown log format: {fmt!r}")

    level = logging.DEBUG if verbose else logging.INFO

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_event,
    ]
    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer() if fmt == "console" else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level)

    # Alembic logs its own progress ("Context impl SQLiteImpl.", …) at INFO, which would
    # otherwise show up in plain `carchive db upgrade` output; -v still surfaces it.
    logging.getLogger("alembic").setLevel(logging.NOTSET if verbose else logging.WARNING)
