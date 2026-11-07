"""Small, dependency-free models used by the Relay developer lab."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Sequence


class IncidentSeverity(str, Enum):
    """Severity labels shared by generated fixtures."""

    SEV1 = "SEV 1"
    SEV2 = "SEV 2"
    SEV3 = "SEV 3"
    SEV4 = "SEV 4"


class ServiceHealth(str, Enum):
    """Health state derived from fixture evidence."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OUTAGE = "outage"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LogEvidence:
    """A normalized log line retained as evidence."""

    timestamp: str
    level: str
    service: str
    message: str
    request_id: str = ""
    trace_id: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceSnapshot:
    """A point-in-time view of one service."""

    name: str
    health: ServiceHealth
    error_rate: float
    latency_ms: float
    active_instances: int
    deployment: str = ""
    dependencies: Sequence[str] = field(default_factory=tuple)

    def is_actionable(self) -> bool:
        """Return whether the snapshot suggests investigation is warranted."""

        return self.health in {ServiceHealth.DEGRADED, ServiceHealth.OUTAGE}


@dataclass(frozen=True)
class IncidentFixture:
    """A complete, serializable incident scenario for local tooling."""

    incident_id: str
    title: str
    severity: IncidentSeverity
    description: str
    primary_service: str
    detected_at: str
    deployment: str
    symptoms: Sequence[str] = field(default_factory=tuple)
    evidence: Sequence[LogEvidence] = field(default_factory=tuple)
    services: Sequence[ServiceSnapshot] = field(default_factory=tuple)
    hypotheses: Sequence[str] = field(default_factory=tuple)
    suggested_checks: Sequence[str] = field(default_factory=tuple)

    @property
    def health(self) -> ServiceHealth:
        """Return the most severe known state in the scenario."""

        states = {item.health for item in self.services}
        if ServiceHealth.OUTAGE in states:
            return ServiceHealth.OUTAGE
        if ServiceHealth.DEGRADED in states:
            return ServiceHealth.DEGRADED
        if ServiceHealth.HEALTHY in states:
            return ServiceHealth.HEALTHY
        return ServiceHealth.UNKNOWN

    def evidence_for(self, service: str) -> tuple[LogEvidence, ...]:
        """Filter evidence by service name."""

        return tuple(item for item in self.evidence if item.service == service)

    def to_dict(self) -> dict[str, object]:
        """Convert the fixture to JSON-friendly primitive values."""

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "primary_service": self.primary_service,
            "detected_at": self.detected_at,
            "deployment": self.deployment,
            "symptoms": list(self.symptoms),
            "evidence": [
                {
                    "timestamp": item.timestamp,
                    "level": item.level,
                    "service": item.service,
                    "message": item.message,
                    "request_id": item.request_id,
                    "trace_id": item.trace_id,
                    "metadata": dict(item.metadata),
                }
                for item in self.evidence
            ],
            "services": [
                {
                    "name": item.name,
                    "health": item.health.value,
                    "error_rate": item.error_rate,
                    "latency_ms": item.latency_ms,
                    "active_instances": item.active_instances,
                    "deployment": item.deployment,
                    "dependencies": list(item.dependencies),
                }
                for item in self.services
            ],
            "hypotheses": list(self.hypotheses),
            "suggested_checks": list(self.suggested_checks),
        }
