import json
import time

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.github_webhook_service import webhook_idempotency_service
from backend.services.webhook_queue_service import webhook_queue_service


client = TestClient(app)


def _sign(secret: str, payload: bytes) -> str:
    import hashlib
    import hmac

    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def setup_function() -> None:
    webhook_idempotency_service.reset_for_testing()
    webhook_queue_service.reset_for_testing()


def test_health_exposes_queue_and_worker_counts() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "queue_depth" in body
    assert "workers_alive" in body


def test_webhook_returns_busy_when_queue_is_overloaded(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setattr(webhook_queue_service, "is_overloaded", lambda: True)

    payload = json.dumps(
        {
            "action": "opened",
            "repository": {"full_name": "acme/widget"},
            "pull_request": {"head": {"sha": "abc123"}},
            "installation": {"id": 42},
        }
    ).encode("utf-8")

    headers = {
        "X-Hub-Signature-256": _sign("test-secret", payload),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-busy",
        "Content-Type": "application/json",
    }

    response = client.post("/github/webhook", content=payload, headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "busy"


def test_queue_visibility_timeout_requeues_unacked_job() -> None:
    webhook_queue_service.enqueue(
        delivery_id="delivery-visibility",
        event="pull_request",
        action="opened",
        repository="acme/widget",
        commit_sha="sha1",
        installation_id=1,
        payload={"action": "opened"},
    )

    first = webhook_queue_service.dequeue_for_worker(timeout_seconds=0, visibility_timeout_seconds=1)
    assert first is not None

    time.sleep(1.1)
    second = webhook_queue_service.dequeue_for_worker(timeout_seconds=0, visibility_timeout_seconds=1)
    assert second is not None
    assert second.job_id == first.job_id
