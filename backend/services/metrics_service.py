from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock

from backend.models.scan_model import CohortMetricsResponse, UserMetricsResponse


@dataclass
class _MetricEvent:
    email: str
    event: str
    scan_id: str | None
    created_at: datetime


class MetricsService:
    SUPPORTED_EVENTS = {
        "scan_started",
        "scan_completed",
        "scan_failed",
        "unlock_clicked",
        "audit_unlocked",
    }

    def __init__(self) -> None:
        self._events: list[_MetricEvent] = []
        self._lock = Lock()

    def record(self, *, email: str, event: str, scan_id: str | None = None) -> None:
        normalized_event = str(event or "").strip().lower()
        if normalized_event not in self.SUPPORTED_EVENTS:
            return
        record = _MetricEvent(
            email=str(email or "").strip().lower(),
            event=normalized_event,
            scan_id=(str(scan_id or "").strip() or None),
            created_at=datetime.now(timezone.utc),
        )
        with self._lock:
            self._events.append(record)

    def user_summary(self, email: str) -> UserMetricsResponse:
        normalized = str(email or "").strip().lower()
        counters = {
            "scan_started": 0,
            "scan_completed": 0,
            "unlock_clicked": 0,
            "audit_unlocked": 0,
        }
        with self._lock:
            for event in self._events:
                if event.email != normalized:
                    continue
                if event.event in counters:
                    counters[event.event] += 1

        return UserMetricsResponse(
            email=normalized,
            scans_started=counters["scan_started"],
            scans_completed=counters["scan_completed"],
            unlock_clicked=counters["unlock_clicked"],
            audit_unlocked=counters["audit_unlocked"],
        )

    @staticmethod
    def _empty_counters() -> dict[str, int]:
        return {
            "scan_started": 0,
            "scan_completed": 0,
            "unlock_clicked": 0,
            "audit_unlocked": 0,
        }

    def _cohort_summary_filtered(self, *, cutoff: datetime | None = None) -> CohortMetricsResponse:
        counters = self._empty_counters()
        users: set[str] = set()
        total_events = 0

        with self._lock:
            for event in self._events:
                if cutoff is not None and event.created_at < cutoff:
                    continue
                total_events += 1
                users.add(event.email)
                if event.event in counters:
                    counters[event.event] += 1

        return CohortMetricsResponse(
            total_events=total_events,
            unique_users=len(users),
            scans_started=counters["scan_started"],
            scans_completed=counters["scan_completed"],
            unlock_clicked=counters["unlock_clicked"],
            audit_unlocked=counters["audit_unlocked"],
        )

    def cohort_summary(self) -> CohortMetricsResponse:
        return self._cohort_summary_filtered(cutoff=None)

    def cohort_summary_since_hours(self, hours: int) -> CohortMetricsResponse:
        normalized_hours = max(0, int(hours))
        if normalized_hours == 0:
            return self._cohort_summary_filtered(cutoff=datetime.now(timezone.utc))
        cutoff = datetime.now(timezone.utc) - timedelta(hours=normalized_hours)
        return self._cohort_summary_filtered(cutoff=cutoff)


metrics_service = MetricsService()
