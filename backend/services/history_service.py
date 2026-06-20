from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import List
from uuid import uuid4

from backend.models.scan_model import ScanHistoryItem, ScanResponse
from backend.services.db import get_scan_db, list_scans_db, save_scan


@dataclass
class UserScanRecord:
    user_email: str
    scan: ScanResponse


@dataclass
class ScanJobRecord:
    user_email: str
    scan_id: str
    github_url: str
    strict_mode: bool
    quick_mode: bool
    status: str
    created_at: datetime
    updated_at: datetime
    stage: str = "queued"
    status_message: str = "Queued for scanning"
    retry_count: int = 0
    result: ScanResponse | None = None
    error: str | None = None


class HistoryService:
    def __init__(self, max_items: int = 200, ttl_hours: int | None = None) -> None:
        self._max_items = max_items
        self._ttl = timedelta(hours=ttl_hours) if ttl_hours is not None else None
        self._items: List[UserScanRecord] = []
        self._jobs: dict[str, ScanJobRecord] = {}
        self._repo_cache: dict[tuple[str, str, bool, bool], tuple[datetime, ScanResponse]] = {}
        self._lock = Lock()

    def _prune_locked(self) -> None:
        if self._ttl is None:
            return
        cutoff = datetime.now(timezone.utc) - self._ttl
        self._items = [item for item in self._items if item.scan.timestamp >= cutoff]
        self._jobs = {k: v for k, v in self._jobs.items() if v.created_at >= cutoff}
        self._repo_cache = {k: v for k, v in self._repo_cache.items() if v[0] >= cutoff}
        if len(self._items) > self._max_items:
            self._items = self._items[-self._max_items :]

    @staticmethod
    def _cache_key(user_email: str, github_url: str, strict_mode: bool = False, quick_mode: bool = False) -> tuple[str, str, bool, bool]:
        return (
            user_email.strip().lower(),
            github_url.strip().lower().rstrip("/"),
            bool(strict_mode),
            bool(quick_mode),
        )

    def start_scan_job(self, user_email: str, github_url: str, strict_mode: bool = False, quick_mode: bool = False) -> str:
        with self._lock:
            self._prune_locked()
            now = datetime.now(timezone.utc)
            scan_id = str(uuid4())
            self._jobs[scan_id] = ScanJobRecord(
                user_email=user_email,
                scan_id=scan_id,
                github_url=github_url,
                strict_mode=bool(strict_mode),
                quick_mode=bool(quick_mode),
                status="pending",
                created_at=now,
                updated_at=now,
            )
            return scan_id

    def mark_scan_running(self, scan_id: str, stage: str = "initializing", message: str = "Initializing scan") -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = "running"
            job.stage = stage
            job.status_message = message
            job.updated_at = datetime.now(timezone.utc)

    def update_scan_stage(self, scan_id: str, stage: str, message: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.stage = str(stage or "running")
            job.status_message = str(message or "Scan in progress")
            if job.status in {"pending", "queued"}:
                job.status = "running"
            job.updated_at = datetime.now(timezone.utc)

    def increment_retry(self, scan_id: str, message: str | None = None) -> int:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return 0
            job.retry_count += 1
            job.stage = "retrying"
            if message:
                job.status_message = message
            job.updated_at = datetime.now(timezone.utc)
            return job.retry_count

    def complete_scan_job(self, user_email: str, scan_id: str, report: ScanResponse) -> None:
        with self._lock:
            self._prune_locked()
            job = self._jobs.get(scan_id)
            if job is None:
                return
            now = datetime.now(timezone.utc)
            job.status = "completed"
            job.stage = "completed"
            job.status_message = "Scan completed"
            job.updated_at = now
            job.result = report
            self._items.append(UserScanRecord(user_email=user_email, scan=report))
            self._repo_cache[self._cache_key(user_email, job.github_url, job.strict_mode, job.quick_mode)] = (now, report)
            self._prune_locked()
        try:
            save_scan(
                user_email=user_email,
                scan_id=report.scan_id,
                github_url=report.github_url,
                repo_name=report.repo_name,
                risk_score=report.risk_score,
                issue_count=report.issue_count,
                timestamp=report.timestamp.isoformat(),
                result_json=report.model_dump_json(),
            )
        except Exception:
            pass

    def fail_scan_job(self, scan_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = "failed"
            job.stage = "failed"
            job.status_message = str(error or "Scan failed")
            job.updated_at = datetime.now(timezone.utc)
            job.error = error

    def get_scan_job(self, user_email: str, scan_id: str) -> ScanJobRecord | None:
        with self._lock:
            self._prune_locked()
            job = self._jobs.get(scan_id)
            if job is None or job.user_email != user_email:
                return None
            return job

    def get_any_scan_job(self, scan_id: str) -> ScanJobRecord | None:
        with self._lock:
            self._prune_locked()
            return self._jobs.get(scan_id)

    def get_cached_report(self, user_email: str, github_url: str, strict_mode: bool = False, quick_mode: bool = False) -> ScanResponse | None:
        with self._lock:
            self._prune_locked()
            cached = self._repo_cache.get(self._cache_key(user_email, github_url, strict_mode, quick_mode))
            if cached is None:
                return None
            return cached[1]

    def attach_cached_report_to_job(self, user_email: str, scan_id: str, report: ScanResponse) -> None:
        cloned = report.model_copy(update={"scan_id": scan_id, "timestamp": datetime.now(timezone.utc)})
        self.complete_scan_job(user_email, scan_id, cloned)

    def add_scan(self, user_email: str, scan: ScanResponse) -> None:
        with self._lock:
            self._items.append(UserScanRecord(user_email=user_email, scan=scan))
            self._prune_locked()
        try:
            save_scan(
                user_email=user_email,
                scan_id=scan.scan_id,
                github_url=scan.github_url,
                repo_name=scan.repo_name,
                risk_score=scan.risk_score,
                issue_count=scan.issue_count,
                timestamp=scan.timestamp.isoformat(),
                result_json=scan.model_dump_json(),
            )
        except Exception:
            pass

    def list_scans(self, user_email: str) -> List[ScanHistoryItem]:
        try:
            rows = list_scans_db(user_email)
            if rows:
                return [
                    ScanHistoryItem(
                        scan_id=r["scan_id"],
                        timestamp=r["timestamp"],
                        github_url=r["github_url"],
                        risk_score=r["risk_score"],
                        issue_count=r["issue_count"],
                    )
                    for r in rows
                ]
        except Exception:
            pass
        with self._lock:
            self._prune_locked()
            filtered = [item.scan for item in self._items if item.user_email == user_email]
            ordered = sorted(filtered, key=lambda item: item.timestamp, reverse=True)
            return [
                ScanHistoryItem(
                    scan_id=item.scan_id,
                    timestamp=item.timestamp,
                    github_url=item.github_url,
                    risk_score=item.risk_score,
                    issue_count=item.issue_count,
                )
                for item in ordered
            ]

    def get_scan(self, user_email: str, scan_id: str) -> ScanResponse | None:
        with self._lock:
            self._prune_locked()
            for item in self._items:
                if item.user_email == user_email and item.scan.scan_id == scan_id:
                    return item.scan
        try:
            result_json = get_scan_db(user_email, scan_id)
            if result_json:
                return ScanResponse.model_validate_json(result_json)
        except Exception:
            pass
        return None

    def get_latest_scan_for_repo(self, github_url: str) -> ScanResponse | None:
        repo_key = str(github_url or "").strip().lower().rstrip("/")
        if not repo_key:
            return None
        with self._lock:
            self._prune_locked()
            matches = [
                item.scan
                for item in self._items
                if str(item.scan.github_url or "").strip().lower().rstrip("/") == repo_key
            ]
            if not matches:
                return None
            matches.sort(key=lambda scan: scan.timestamp, reverse=True)
            return matches[0]

    def count_scans_today(self, user_email: str) -> int:
        with self._lock:
            self._prune_locked()
            start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            return sum(
                1
                for item in self._items
                if item.user_email == user_email and item.scan.timestamp >= start_of_day
            )

history_service = HistoryService()
