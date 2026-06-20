from __future__ import annotations

from backend.services.webhook_queue_service import webhook_queue_service
from backend.services.worker_heartbeat_service import worker_heartbeat_service


def dequeue_job(timeout: int = 5):
    return webhook_queue_service.dequeue_for_worker(timeout_seconds=timeout)


def mark_done(job_id: str, metadata: dict | None = None) -> None:
    webhook_queue_service.mark_done(str(job_id or ""), metadata=metadata)


def mark_failed(job_id: str, error: str, metadata: dict | None = None) -> None:
    webhook_queue_service.mark_failed(str(job_id or ""), str(error or ""), metadata=metadata)


def get_queue_depth() -> int:
    return webhook_queue_service.size()


def get_worker_count() -> int:
    return worker_heartbeat_service.active_workers()
