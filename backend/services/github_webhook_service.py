from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from threading import Lock

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    redis = None


class WebhookSignatureError(Exception):
    pass


class WebhookIdempotencyService:
    def __init__(self) -> None:
        self._processed: dict[str, datetime] = {}
        self._lock = Lock()
        self._redis = None
        self._prefix = str(os.getenv("WEBHOOK_DELIVERY_KEY_PREFIX", "repoguard:webhook:delivery")).strip() or "repoguard:webhook:delivery"

        redis_url = str(os.getenv("REDIS_URL", "")).strip()
        if redis_url and redis is not None:
            try:
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    def _prune_locked(self, now: datetime) -> None:
        expired = [delivery_id for delivery_id, expires_at in self._processed.items() if expires_at <= now]
        for delivery_id in expired:
            self._processed.pop(delivery_id, None)

    def mark_if_new(self, delivery_id: str, ttl_seconds: int = 24 * 60 * 60) -> bool:
        normalized = str(delivery_id or "").strip()
        if not normalized:
            return False

        if self._redis is not None:
            key = f"{self._prefix}:{normalized}"
            return bool(self._redis.set(key, "1", nx=True, ex=max(1, int(ttl_seconds))))

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=max(1, int(ttl_seconds)))

        with self._lock:
            self._prune_locked(now)
            if normalized in self._processed:
                return False
            self._processed[normalized] = expires_at
            return True

    def reset_for_testing(self) -> None:
        if self._redis is not None:
            for key in self._redis.scan_iter(match=f"{self._prefix}:*"):
                self._redis.delete(key)
            return
        with self._lock:
            self._processed.clear()


def _webhook_secret() -> str:
    return str(os.getenv("GITHUB_APP_WEBHOOK_SECRET", "")).strip()


def verify_webhook_signature(payload: bytes, signature_header: str | None) -> None:
    secret = _webhook_secret()
    if not secret:
        raise WebhookSignatureError("Webhook secret is not configured")

    signature = str(signature_header or "").strip()
    if not signature.startswith("sha256="):
        raise WebhookSignatureError("Missing sha256 webhook signature")

    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    if not hmac.compare_digest(expected, signature):
        raise WebhookSignatureError("Invalid webhook signature")


webhook_idempotency_service = WebhookIdempotencyService()
