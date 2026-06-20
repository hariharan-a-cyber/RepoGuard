from __future__ import annotations

import os
import time
from threading import Lock

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    redis = None


class WorkerHeartbeatService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._beats: dict[str, float] = {}
        self._ttl_seconds = max(5, int(str(os.getenv("WORKER_HEARTBEAT_TTL_SECONDS", "30")).strip() or "30"))
        self._prefix = str(os.getenv("WORKER_HEARTBEAT_KEY_PREFIX", "repoguard:worker:hb")).strip() or "repoguard:worker:hb"
        self._redis = None

        redis_url = str(os.getenv("REDIS_URL", "")).strip()
        if redis_url and redis is not None:
            try:
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    def beat(self, worker_id: str) -> None:
        normalized = str(worker_id or "").strip()
        if not normalized:
            return
        now = time.time()

        if self._redis is not None:
            self._redis.set(f"{self._prefix}:{normalized}", str(int(now)), ex=self._ttl_seconds)
            return

        with self._lock:
            self._beats[normalized] = now

    def active_workers(self) -> int:
        if self._redis is not None:
            return sum(1 for _ in self._redis.scan_iter(match=f"{self._prefix}:*"))

        now = time.time()
        cutoff = now - float(self._ttl_seconds)
        with self._lock:
            expired = [worker_id for worker_id, ts in self._beats.items() if ts < cutoff]
            for worker_id in expired:
                self._beats.pop(worker_id, None)
            return len(self._beats)


worker_heartbeat_service = WorkerHeartbeatService()
