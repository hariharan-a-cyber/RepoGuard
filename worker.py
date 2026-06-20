from __future__ import annotations

import os
import threading
import time
from uuid import uuid4

from backend.services.queue_client import dequeue_job, mark_done, mark_failed
from backend.services.webhook_queue_service import webhook_queue_service
from backend.services.webhook_worker_service import webhook_worker_service
from backend.services.worker_heartbeat_service import worker_heartbeat_service

TRANSIENT_FAILURE_TYPES = {"network_failure", "osv_timeout", "github_api_failure"}
MAX_RETRIES = 2


def _worker_loop(worker_id: str) -> None:
    while True:
        worker_heartbeat_service.beat(worker_id)
        try:
            job = dequeue_job(timeout=5)
        except Exception:
            # Redis/network hiccups should not kill the worker loop.
            time.sleep(1.0)
            continue
        if not job:
            continue

        attempts = int((job.payload or {}).get("_attempts") or 1)

        try:
            result = webhook_worker_service.process_job(job)
            if result.status == "completed" or result.status == "skipped":
                mark_done(
                    job.job_id,
                    metadata={
                        "repo": result.repository,
                        "commit": result.commit_sha,
                        "duration_seconds": result.duration_seconds,
                    },
                )
            else:
                should_retry = result.retryable and result.failure_type in TRANSIENT_FAILURE_TYPES and attempts <= MAX_RETRIES
                if should_retry:
                    backoff_seconds = float(2 ** max(0, attempts - 1))
                    time.sleep(backoff_seconds)
                    webhook_queue_service.enqueue(
                        delivery_id=job.delivery_id,
                        event=job.event,
                        action=job.action,
                        repository=job.repository,
                        commit_sha=job.commit_sha,
                        installation_id=job.installation_id,
                        payload={**job.payload, "_attempts": attempts},
                    )
                    mark_failed(
                        job.job_id,
                        result.message,
                        metadata={
                            "repo": result.repository,
                            "commit": result.commit_sha,
                            "duration_seconds": result.duration_seconds,
                            "failure_reason": f"retrying:{result.failure_type}",
                        },
                    )
                else:
                    mark_failed(
                        job.job_id,
                        result.message,
                        metadata={
                            "repo": result.repository,
                            "commit": result.commit_sha,
                            "duration_seconds": result.duration_seconds,
                            "failure_reason": result.failure_type or "failed",
                        },
                    )
        except Exception as exc:
            mark_failed(
                job.job_id,
                str(exc),
                metadata={
                    "repo": job.repository,
                    "commit": job.commit_sha,
                    "duration_seconds": 0.0,
                    "failure_reason": "worker_exception",
                },
            )

        worker_heartbeat_service.beat(worker_id)


def main() -> None:
    cpu_cores = os.cpu_count() or 2
    default_count = min(cpu_cores, 2)
    configured = int(str(os.getenv("WORKER_CONCURRENCY", str(default_count))).strip() or str(default_count))
    concurrency = max(1, min(configured, 2))

    threads: list[threading.Thread] = []
    for _ in range(concurrency):
        worker_id = f"worker-{uuid4()}"
        thread = threading.Thread(target=_worker_loop, args=(worker_id,), daemon=True)
        thread.start()
        threads.append(thread)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
