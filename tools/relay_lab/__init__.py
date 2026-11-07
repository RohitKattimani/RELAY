"""Standalone developer helpers for experimenting with Relay data.

The package is intentionally isolated from the application runtime. It has no
third-party dependencies and is not imported by the backend or frontend.
"""

from .fixture_builder import ScenarioBuilder, build_incident_fixture
from .log_parser import parse_log_lines
from .models import IncidentFixture, IncidentSeverity, LogEvidence, ServiceHealth
from .report import render_incident_report

__all__ = [
    "IncidentFixture",
    "IncidentSeverity",
    "LogEvidence",
    "ScenarioBuilder",
    "ServiceHealth",
    "build_incident_fixture",
    "parse_log_lines",
    "render_incident_report",
]
