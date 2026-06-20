from __future__ import annotations

from datetime import datetime, timezone

from backend.models.scan_model import AnalyticsSummaryResponse
from backend.services.metrics_service import MetricsService
from backend.services.metrics_service import metrics_service


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((float(numerator) / float(denominator)) * 100.0, 2)


class AnalyticsService:
    def __init__(self, metrics: MetricsService) -> None:
        self._metrics = metrics

    def summary(self) -> AnalyticsSummaryResponse:
        cohort = self._metrics.cohort_summary()
        cohort_24h = self._metrics.cohort_summary_since_hours(24)
        cohort_7d = self._metrics.cohort_summary_since_hours(24 * 7)
        return AnalyticsSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            cohort=cohort,
            cohort_24h=cohort_24h,
            cohort_7d=cohort_7d,
            completion_rate=_ratio(cohort.scans_completed, cohort.scans_started),
            completion_rate_24h=_ratio(cohort_24h.scans_completed, cohort_24h.scans_started),
            completion_rate_7d=_ratio(cohort_7d.scans_completed, cohort_7d.scans_started),
            unlock_click_through_rate=_ratio(cohort.unlock_clicked, cohort.scans_completed),
            unlock_click_through_rate_24h=_ratio(cohort_24h.unlock_clicked, cohort_24h.scans_completed),
            unlock_click_through_rate_7d=_ratio(cohort_7d.unlock_clicked, cohort_7d.scans_completed),
            unlock_conversion_rate=_ratio(cohort.audit_unlocked, cohort.unlock_clicked),
            unlock_conversion_rate_24h=_ratio(cohort_24h.audit_unlocked, cohort_24h.unlock_clicked),
            unlock_conversion_rate_7d=_ratio(cohort_7d.audit_unlocked, cohort_7d.unlock_clicked),
        )

    def export_csv(self) -> str:
        summary = self.summary()
        cohort = summary.cohort
        header = [
            "generated_at",
            "total_events",
            "unique_users",
            "scans_started",
            "scans_completed",
            "unlock_clicked",
            "audit_unlocked",
            "events_24h",
            "events_7d",
            "scans_started_24h",
            "scans_started_7d",
            "scans_completed_24h",
            "scans_completed_7d",
            "completion_rate",
            "completion_rate_24h",
            "completion_rate_7d",
            "unlock_click_through_rate",
            "unlock_click_through_rate_24h",
            "unlock_click_through_rate_7d",
            "unlock_conversion_rate",
            "unlock_conversion_rate_24h",
            "unlock_conversion_rate_7d",
        ]
        row = [
            summary.generated_at.isoformat(),
            str(cohort.total_events),
            str(cohort.unique_users),
            str(cohort.scans_started),
            str(cohort.scans_completed),
            str(cohort.unlock_clicked),
            str(cohort.audit_unlocked),
            str(summary.cohort_24h.total_events),
            str(summary.cohort_7d.total_events),
            str(summary.cohort_24h.scans_started),
            str(summary.cohort_7d.scans_started),
            str(summary.cohort_24h.scans_completed),
            str(summary.cohort_7d.scans_completed),
            f"{summary.completion_rate:.2f}",
            f"{summary.completion_rate_24h:.2f}",
            f"{summary.completion_rate_7d:.2f}",
            f"{summary.unlock_click_through_rate:.2f}",
            f"{summary.unlock_click_through_rate_24h:.2f}",
            f"{summary.unlock_click_through_rate_7d:.2f}",
            f"{summary.unlock_conversion_rate:.2f}",
            f"{summary.unlock_conversion_rate_24h:.2f}",
            f"{summary.unlock_conversion_rate_7d:.2f}",
        ]
        return ",".join(header) + "\n" + ",".join(row) + "\n"


analytics_service = AnalyticsService(metrics=metrics_service)
