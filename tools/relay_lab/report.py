"""Human-readable reports for the standalone Relay developer lab."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Literal

from .models import IncidentFixture, LogEvidence, ServiceHealth


OutputFormat = Literal["text", "json"]


def _line(label: str, value: object, width: int = 18) -> str:
    """Align a report field for terminal readability."""

    return f"{label:<{width}} {value}"


def _render_evidence(events: Iterable[LogEvidence]) -> list[str]:
    """Render a compact evidence section."""

    lines = ["Evidence"]
    for event in events:
        identity = event.request_id or event.trace_id or "no-correlation-id"
        lines.append(
            f"  [{event.level:<5}] {event.timestamp or 'unknown-time'} "
            f"{event.service} ({identity})"
        )
        lines.append(f"          {event.message}")
    return lines


def _render_services(fixture: IncidentFixture) -> list[str]:
    """Render service health and measured values."""

    lines = ["Services"]
    for service in fixture.services:
        dependencies = ", ".join(service.dependencies) or "none recorded"
        lines.append(
            f"  {service.name}: {service.health.value} | "
            f"errors={service.error_rate:.2%} | latency={service.latency_ms:.0f}ms"
        )
        lines.append(
            f"      instances={service.active_instances} | "
            f"deployment={service.deployment or 'unknown'} | deps={dependencies}"
        )
    return lines


def render_text_report(fixture: IncidentFixture) -> str:
    """Render an incident fixture as a terminal-friendly report."""

    lines = [
        "RELAY INCIDENT LAB",
        "=" * 72,
        _line("Incident", fixture.incident_id),
        _line("Title", fixture.title),
        _line("Severity", fixture.severity.value),
        _line("Health", fixture.health.value),
        _line("Service", fixture.primary_service),
        _line("Detected", fixture.detected_at),
        _line("Deployment", fixture.deployment),
        "",
        fixture.description,
        "",
        "Symptoms",
        *[f"  - {item}" for item in fixture.symptoms],
        "",
        *_render_services(fixture),
        "",
        *_render_evidence(fixture.evidence),
        "",
        "Hypotheses",
        *[f"  - {item}" for item in fixture.hypotheses],
        "",
        "Suggested checks",
        *[f"  {index}. {item}" for index, item in enumerate(fixture.suggested_checks, 1)],
    ]
    return "\n".join(lines)


def render_incident_report(
    fixture: IncidentFixture,
    output_format: OutputFormat = "text",
) -> str:
    """Render a fixture as text or stable, indented JSON."""

    if output_format == "json":
        return json.dumps(fixture.to_dict(), indent=2, sort_keys=True)
    if output_format != "text":
        raise ValueError(f"Unsupported report format: {output_format}")
    return render_text_report(fixture)


def health_summary(fixture: IncidentFixture) -> dict[str, int]:
    """Count service snapshots by health state."""

    summary = {state.value: 0 for state in ServiceHealth}
    for service in fixture.services:
        summary[service.health.value] += 1
    return summary
