"""Dependency-free parsing helpers for common structured application logs."""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from .models import LogEvidence


_HEADER = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<service>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<body>.*)$",
    re.IGNORECASE,
)
_KEY_VALUE = re.compile(r"(?P<key>[a-zA-Z_][\w.-]*)=(?P<value>\"[^\"]*\"|\S+)")
_REQUEST_KEYS = ("request_id", "requestId", "x_request_id")
_TRACE_KEYS = ("trace_id", "traceId", "trace")


def _strip_quotes(value: str) -> str:
    """Remove optional double quotes from a key-value value."""

    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _metadata(body: str) -> dict[str, str]:
    """Extract key-value pairs without changing the original message."""

    return {
        match.group("key"): _strip_quotes(match.group("value"))
        for match in _KEY_VALUE.finditer(body)
    }


def _first_value(values: dict[str, str], keys: tuple[str, ...]) -> str:
    """Return the first matching value from a set of common key spellings."""

    for key in keys:
        if key in values:
            return values[key]
    return ""


def parse_log_line(line: str, default_service: str = "unknown") -> LogEvidence:
    """Parse one log line, preserving malformed lines as usable evidence."""

    raw = line.strip()
    match = _HEADER.match(raw)
    if not match:
        return LogEvidence(
            timestamp="",
            level="UNKNOWN",
            service=default_service,
            message=raw,
        )
    body = match.group("body")
    values = _metadata(body)
    return LogEvidence(
        timestamp=match.group("timestamp"),
        level=match.group("level").upper().replace("WARNING", "WARN"),
        service=match.group("service"),
        message=body,
        request_id=_first_value(values, _REQUEST_KEYS),
        trace_id=_first_value(values, _TRACE_KEYS),
        metadata=values,
    )


def parse_log_lines(
    lines: Iterable[str],
    default_service: str = "unknown",
) -> tuple[LogEvidence, ...]:
    """Parse an iterable of lines into immutable evidence records."""

    return tuple(parse_log_line(line, default_service) for line in lines if line.strip())


def iter_errors(events: Iterable[LogEvidence]) -> Iterator[LogEvidence]:
    """Yield error-level events from a parsed event stream."""

    return (
        event
        for event in events
        if event.level in {"ERROR", "FATAL"}
    )


def group_by_service(
    events: Iterable[LogEvidence],
) -> dict[str, tuple[LogEvidence, ...]]:
    """Group parsed events by their normalized service name."""

    grouped: dict[str, list[LogEvidence]] = {}
    for event in events:
        grouped.setdefault(event.service, []).append(event)
    return {service: tuple(items) for service, items in grouped.items()}


def summarize_levels(events: Iterable[LogEvidence]) -> dict[str, int]:
    """Count events by log level."""

    counts: dict[str, int] = {}
    for event in events:
        counts[event.level] = counts.get(event.level, 0) + 1
    return counts
