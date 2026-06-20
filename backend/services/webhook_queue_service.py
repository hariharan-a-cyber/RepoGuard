from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    redis = None


@dataclass
class WebhookQueueJob:
    job_id: str
    queued_at: datetime
    delivery_id: str
    event: str
    action: str
    repository: str
    commit_sha: str
    installation_id: int | None
    payload: dict


class WebhookQueueService:
    def __init__(self) -> None:
        self._items: list[WebhookQueueJob] = []
        self._inflight: dict[str, tuple[float, WebhookQueueJob]] = {}
        self._failed: dict[str, str] = {}
        self._lock = Lock()
        self._queue_key = str(os.getenv("WEBHOOK_QUEUE_KEY", "repoguard:webhook:queue")).strip() or "repoguard:webhook:queue"
        self._processing_hash_key = str(os.getenv("WEBHOOK_PROCESSING_HASH_KEY", "repoguard:webhook:processing")).strip() or "repoguard:webhook:processing"
        self._processing_zset_key = str(os.getenv("WEBHOOK_PROCESSING_ZSET_KEY", "repoguard:webhook:processing-leases")).strip() or "repoguard:webhook:processing-leases"
        self._failed_hash_key = str(os.getenv("WEBHOOK_FAILED_HASH_KEY", "repoguard:webhook:failed")).strip() or "repoguard:webhook:failed"
        self._job_status_hash_key = str(os.getenv("WEBHOOK_JOB_STATUS_HASH_KEY", "repoguard:webhook:job-status")).strip() or "repoguard:webhook:job-status"
        self._redis = None

        redis_url = str(os.getenv("REDIS_URL", "")).strip()
        if redis_url and redis is not None:
            try:
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    @staticmethod
    def _serialize(job: WebhookQueueJob) -> str:
        payload = {
            "job_id": job.job_id,
            "queued_at": job.queued_at.isoformat(),
            "delivery_id": job.delivery_id,
            "event": job.event,
            "action": job.action,
            "repository": job.repository,
            "commit_sha": job.commit_sha,
            "installation_id": job.installation_id,
            "payload": job.payload,
            "attempts": int(job.payload.get("_attempts", 0)) if isinstance(job.payload, dict) else 0,
        }
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def _deserialize(raw: str) -> WebhookQueueJob:
        data = json.loads(raw)
        queued_at_raw = str(data.get("queued_at") or "")
        if queued_at_raw.endswith("Z"):
            queued_at_raw = queued_at_raw[:-1] + "+00:00"
        queued_at = datetime.fromisoformat(queued_at_raw) if queued_at_raw else datetime.now(timezone.utc)
        if queued_at.tzinfo is None:
            queued_at = queued_at.replace(tzinfo=timezone.utc)

        return WebhookQueueJob(
            job_id=str(data.get("job_id") or "").strip() or str(uuid4()),
            queued_at=queued_at,
            delivery_id=str(data.get("delivery_id") or "").strip(),
            event=str(data.get("event") or "").strip(),
            action=str(data.get("action") or "").strip(),
            repository=str(data.get("repository") or "").strip(),
            commit_sha=str(data.get("commit_sha") or "").strip(),
            installation_id=data.get("installation_id") if isinstance(data.get("installation_id"), int) else None,
            payload={
                **(data.get("payload") if isinstance(data.get("payload"), dict) else {}),
                "_attempts": int(data.get("attempts") or 0),
            },
        )

    @staticmethod
    def _inflight_lease_deadline(now: float, visibility_timeout_seconds: int) -> float:
        return now + float(max(1, int(visibility_timeout_seconds)))

    def _requeue_expired_inflight(self, now_epoch: float) -> None:
        if self._redis is not None:
            expired_job_ids = self._redis.zrangebyscore(self._processing_zset_key, min="-inf", max=str(now_epoch))
            for job_id in expired_job_ids:
                raw = self._redis.hget(self._processing_hash_key, job_id)
                if raw:
                    self._redis.rpush(self._queue_key, raw)
                self._redis.hdel(self._processing_hash_key, job_id)
                self._redis.zrem(self._processing_zset_key, job_id)
            return

        with self._lock:
            expired = [job_id for job_id, (lease_deadline, _) in self._inflight.items() if lease_deadline <= now_epoch]
            for job_id in expired:
                _, job = self._inflight.pop(job_id)
                self._items.append(job)

    def enqueue(self, *, delivery_id: str, event: str, action: str, repository: str, commit_sha: str, installation_id: int | None, payload: dict) -> WebhookQueueJob:
        job = WebhookQueueJob(
            job_id=str(uuid4()),
            queued_at=datetime.now(timezone.utc),
            delivery_id=str(delivery_id or "").strip(),
            event=str(event or "").strip(),
            action=str(action or "").strip(),
            repository=str(repository or "").strip(),
            commit_sha=str(commit_sha or "").strip(),
            installation_id=installation_id,
            payload=payload,
        )

        if self._redis is not None:
            self._redis.rpush(self._queue_key, self._serialize(job))
            self._set_job_status(
                job.job_id,
                {
                    "job_id": job.job_id,
                    "state": "queued",
                    "repo": job.repository,
                    "commit": job.commit_sha,
                    "failure_reason": "",
                    "duration_seconds": 0.0,
                },
            )
            return job

        with self._lock:
            self._items.append(job)
            self._failed.pop(job.job_id, None)
            self._set_job_status(
                job.job_id,
                {
                    "job_id": job.job_id,
                    "state": "queued",
                    "repo": job.repository,
                    "commit": job.commit_sha,
                    "failure_reason": "",
                    "duration_seconds": 0.0,
                },
            )
        return job

    def size(self) -> int:
        if self._redis is not None:
            return int(self._redis.llen(self._queue_key))
        with self._lock:
            return len(self._items)

    def pop_next(self) -> WebhookQueueJob | None:
        if self._redis is not None:
            raw = self._redis.lpop(self._queue_key)
            if raw is None:
                return None
            return self._deserialize(str(raw))

        with self._lock:
            if not self._items:
                return None
            return self._items.pop(0)

    def dequeue_for_worker(self, timeout_seconds: int = 5, visibility_timeout_seconds: int = 60) -> WebhookQueueJob | None:
        now_epoch = datetime.now(timezone.utc).timestamp()
        self._requeue_expired_inflight(now_epoch)

        # Apply worker-side inflight backpressure so ingress can still queue bursts.
        if self.current_inflight() >= self.max_inflight():
            return None

        if self._redis is not None:
            try:
                raw_item = self._redis.blpop(self._queue_key, timeout=max(0, int(timeout_seconds)))
            except Exception:
                # Treat transient redis disconnects as empty dequeue; worker loop will retry.
                return None
            if not raw_item:
                return None
            _, raw = raw_item
            job = self._deserialize(str(raw))
            attempts = int((job.payload or {}).get("_attempts") or 0) + 1
            job.payload["_attempts"] = attempts
            leased_raw = self._serialize(job)
            lease_deadline = self._inflight_lease_deadline(now_epoch, visibility_timeout_seconds)
            self._redis.hset(self._processing_hash_key, job.job_id, leased_raw)
            self._redis.zadd(self._processing_zset_key, {job.job_id: lease_deadline})
            self._set_job_status(
                job.job_id,
                {
                    "job_id": job.job_id,
                    "state": "processing",
                    "repo": job.repository,
                    "commit": job.commit_sha,
                    "failure_reason": "",
                    "duration_seconds": 0.0,
                },
            )
            return job

        with self._lock:
            if not self._items:
                return None
            job = self._items.pop(0)
            attempts = int((job.payload or {}).get("_attempts") or 0) + 1
            job.payload["_attempts"] = attempts
            lease_deadline = self._inflight_lease_deadline(now_epoch, visibility_timeout_seconds)
            self._inflight[job.job_id] = (lease_deadline, job)
            self._set_job_status(
                job.job_id,
                {
                    "job_id": job.job_id,
                    "state": "processing",
                    "repo": job.repository,
                    "commit": job.commit_sha,
                    "failure_reason": "",
                    "duration_seconds": 0.0,
                },
            )
            return job

    def mark_done(self, job_id: str, metadata: dict | None = None) -> None:
        normalized = str(job_id or "").strip()
        if not normalized:
            return

        metadata = metadata if isinstance(metadata, dict) else {}
        self._set_job_status(
            normalized,
            {
                "job_id": normalized,
                "state": "done",
                "repo": str(metadata.get("repo") or ""),
                "commit": str(metadata.get("commit") or ""),
                "failure_reason": "",
                "duration_seconds": float(metadata.get("duration_seconds") or 0.0),
            },
        )

        if self._redis is not None:
            self._redis.hdel(self._processing_hash_key, normalized)
            self._redis.zrem(self._processing_zset_key, normalized)
            return

        with self._lock:
            self._inflight.pop(normalized, None)

    def mark_failed(self, job_id: str, error_message: str, metadata: dict | None = None) -> None:
        normalized = str(job_id or "").strip()
        if not normalized:
            return

        metadata = metadata if isinstance(metadata, dict) else {}
        failure_reason = str(metadata.get("failure_reason") or error_message or "").strip()

        self.mark_done(normalized, metadata={
            "repo": str(metadata.get("repo") or ""),
            "commit": str(metadata.get("commit") or ""),
            "duration_seconds": float(metadata.get("duration_seconds") or 0.0),
        })

        self._set_job_status(
            normalized,
            {
                "job_id": normalized,
                "state": "failed",
                "repo": str(metadata.get("repo") or ""),
                "commit": str(metadata.get("commit") or ""),
                "failure_reason": failure_reason,
                "duration_seconds": float(metadata.get("duration_seconds") or 0.0),
            },
        )

        if self._redis is not None:
            self._redis.hset(self._failed_hash_key, normalized, str(error_message or ""))
            return

        with self._lock:
            self._failed[normalized] = str(error_message or "")

    def max_queue_depth(self) -> int:
        return max(1, int(str(os.getenv("WEBHOOK_MAX_QUEUE_DEPTH", "200")).strip() or "200"))

    def max_inflight(self) -> int:
        return max(1, int(str(os.getenv("WEBHOOK_MAX_INFLIGHT", "2")).strip() or "2"))

    def current_inflight(self) -> int:
        if self._redis is not None:
            return int(self._redis.zcard(self._processing_zset_key))
        with self._lock:
            return len(self._inflight)

    def is_overloaded(self) -> bool:
        return self.size() >= self.max_queue_depth()

    def _set_job_status(self, job_id: str, payload: dict) -> None:
        if self._redis is not None:
            self._redis.hset(self._job_status_hash_key, str(job_id), json.dumps(payload, separators=(",", ":")))
            return
        self._failed[str(job_id)] = self._failed.get(str(job_id), "")
        setattr(self, "_job_status", getattr(self, "_job_status", {}))
        getattr(self, "_job_status")[str(job_id)] = payload

    def get_job_status(self, job_id: str) -> dict | None:
        normalized = str(job_id or "").strip()
        if not normalized:
            return None
        if self._redis is not None:
            raw = self._redis.hget(self._job_status_hash_key, normalized)
            if not raw:
                return None
            try:
                return json.loads(str(raw))
            except Exception:
                return None

        with self._lock:
            statuses = getattr(self, "_job_status", {})
            return statuses.get(normalized)

    def reset_for_testing(self) -> None:
        if self._redis is not None:
            self._redis.delete(self._queue_key)
            self._redis.delete(self._processing_hash_key)
            self._redis.delete(self._processing_zset_key)
            self._redis.delete(self._failed_hash_key)
            self._redis.delete(self._job_status_hash_key)
            return
        with self._lock:
            self._items.clear()
            self._inflight.clear()
            self._failed.clear()
            setattr(self, "_job_status", {})


webhook_queue_service = WebhookQueueService()
