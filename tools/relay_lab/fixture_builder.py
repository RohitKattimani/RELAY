"""Deterministic builders for local incident-analysis fixtures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .log_parser import parse_log_lines
from .models import (
    IncidentFixture,
    IncidentSeverity,
    ServiceHealth,
    ServiceSnapshot,
)


_DEFAULT_LOGS = (
    "2026-11-07T14:02:11.482Z checkout-api ERROR request_id=req-7f3c upstream_status=500 path=/v1/checkout",
    "2026-11-07T14:02:14.019Z checkout-api ERROR trace_id=tr-4b91 database_code=53300 message=\"connection slots reserved\"",
    "2026-11-07T14:02:19.774Z ingress-nginx WARN trace_id=tr-4b91 upstream_timeout_ms=30000",
)


@dataclass
class ScenarioBuilder:
    """Mutable builder that produces immutable incident fixtures."""

    incident_id: str = "INC-LAB-0001"
    title: str = "Checkout failures after deployment"
    severity: IncidentSeverity = IncidentSeverity.SEV1
    description: str = "Checkout requests fail after a production rollout."
    primary_service: str = "checkout-api"
    detected_at: str = "2026-11-07T14:02:11Z"
    deployment: str = "8f2c1a"
    _logs: list[str] = field(default_factory=list)
    _symptoms: list[str] = field(default_factory=list)
    _hypotheses: list[str] = field(default_factory=list)
    _checks: list[str] = field(default_factory=list)
    _services: list[ServiceSnapshot] = field(default_factory=list)

    def with_identity(self, incident_id: str, title: str) -> "ScenarioBuilder":
        self.incident_id = incident_id
        self.title = title
        return self

    def with_logs(self, *lines: str) -> "ScenarioBuilder":
        self._logs.extend(lines)
        return self

    def with_symptoms(self, *items: str) -> "ScenarioBuilder":
        self._symptoms.extend(items)
        return self

    def with_hypotheses(self, *items: str) -> "ScenarioBuilder":
        self._hypotheses.extend(items)
        return self

    def with_checks(self, *items: str) -> "ScenarioBuilder":
        self._checks.extend(items)
        return self

    def add_service(
        self,
        name: str,
        health: ServiceHealth,
        error_rate: float,
        latency_ms: float,
        active_instances: int,
        deployment: str = "",
        dependencies: Sequence[str] = (),
    ) -> "ScenarioBuilder":
        self._services.append(
            ServiceSnapshot(
                name=name,
                health=health,
                error_rate=error_rate,
                latency_ms=latency_ms,
                active_instances=active_instances,
                deployment=deployment,
                dependencies=tuple(dependencies),
            )
        )
        return self

    def build(self) -> IncidentFixture:
        """Build a fixture, supplying sensible evidence defaults."""

        raw_logs = tuple(self._logs) or _DEFAULT_LOGS
        evidence = parse_log_lines(raw_logs, self.primary_service)
        services = tuple(self._services) or (
            ServiceSnapshot(
                name=self.primary_service,
                health=ServiceHealth.OUTAGE,
                error_rate=0.42,
                latency_ms=1842,
                active_instances=6,
                deployment=self.deployment,
                dependencies=("postgres-primary", "redis-cache"),
            ),
        )
        return IncidentFixture(
            incident_id=self.incident_id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            primary_service=self.primary_service,
            detected_at=self.detected_at,
            deployment=self.deployment,
            symptoms=tuple(self._symptoms) or (
                "HTTP 500 responses on checkout requests",
                "Upstream request timeouts",
                "Database connection allocation errors",
            ),
            evidence=evidence,
            services=services,
            hypotheses=tuple(self._hypotheses) or (
                "Connection pool settings changed during the rollout",
                "Database capacity is exhausted by a new request path",
            ),
            suggested_checks=tuple(self._checks) or (
                "Compare pool configuration with the previous revision",
                "Run read-only connection and latency diagnostics",
                "Validate the candidate fix in an isolated environment",
            ),
        )


def build_incident_fixture(
    incident_id: str = "INC-LAB-0001",
    deployment: str = "8f2c1a",
) -> IncidentFixture:
    """Return the canonical local fixture used by developer examples."""

    return (
        ScenarioBuilder(incident_id=incident_id, deployment=deployment)
        .with_symptoms(
            "HTTP 500 responses on checkout requests",
            "Database connection allocation errors",
        )
        .with_hypotheses(
            "Connection pool settings changed during the rollout",
            "Database capacity is exhausted by a new request path",
        )
        .build()
    )
