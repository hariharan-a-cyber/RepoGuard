import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.github_webhook_service import webhook_idempotency_service
from backend.services.webhook_queue_service import webhook_queue_service


client = TestClient(app)


def _sign(secret: str, payload: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _headers(secret: str, payload: bytes, delivery_id: str = "delivery-1") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": _sign(secret, payload),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "Content-Type": "application/json",
    }


def _payload(action: str = "opened") -> dict:
    return {
        "action": action,
        "repository": {"full_name": "acme/widget"},
        "pull_request": {"head": {"sha": "abc123def"}},
        "installation": {"id": 42},
    }


def setup_function() -> None:
    webhook_idempotency_service.reset_for_testing()
    webhook_queue_service.reset_for_testing()


def test_webhook_enqueues_signed_pull_request_event(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")

    payload_dict = _payload("opened")
    payload = json.dumps(payload_dict).encode("utf-8")

    response = client.post("/github/webhook", content=payload, headers=_headers("test-secret", payload))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert body["delivery_id"] == "delivery-1"
    assert body["queue_size"] == 1

    queued = webhook_queue_service.pop_next()
    assert queued is not None
    assert queued.delivery_id == "delivery-1"
    assert queued.event == "pull_request"
    assert queued.action == "opened"
    assert queued.repository == "acme/widget"
    assert queued.commit_sha == "abc123def"
    assert queued.installation_id == 42


def test_webhook_is_idempotent_by_delivery_id(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")

    payload = json.dumps(_payload("synchronize")).encode("utf-8")
    headers = _headers("test-secret", payload, delivery_id="dup-1")

    first = client.post("/github/webhook", content=payload, headers=headers)
    second = client.post("/github/webhook", content=payload, headers=headers)

    assert first.status_code == 200
    assert first.json()["status"] == "accepted"

    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"

    assert webhook_queue_service.size() == 1


def test_webhook_rejects_invalid_signature(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")

    payload = json.dumps(_payload("opened")).encode("utf-8")
    bad_headers = {
        "X-Hub-Signature-256": "sha256=bad",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-bad",
        "Content-Type": "application/json",
    }

    response = client.post("/github/webhook", content=payload, headers=bad_headers)

    assert response.status_code == 401
    assert "Invalid webhook signature" in response.json()["detail"]
