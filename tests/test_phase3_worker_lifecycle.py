from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.github_app_auth_service import (
    InstallationTokenRecord,
    github_app_auth_service,
)
from backend.services.github_check_run_service import github_check_run_service
from backend.services.github_service import GithubService
from backend.services.scanner_service import ScannerService
from backend.services.github_webhook_service import webhook_idempotency_service
from backend.services.webhook_queue_service import webhook_queue_service
from backend.services.webhook_worker_service import MAX_RETRIES, WorkerRunResult, webhook_worker_service


client = TestClient(app)


def setup_function() -> None:
    webhook_idempotency_service.reset_for_testing()
    webhook_queue_service.reset_for_testing()
    github_app_auth_service.reset_for_testing()
    github_check_run_service.reset_for_testing()
    webhook_worker_service._disable_subprocess_scan = False


def test_installation_token_cache_reuses_token_until_refresh_boundary(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_exchange(installation_id: int) -> InstallationTokenRecord:
        calls["count"] += 1
        return InstallationTokenRecord(
            token=f"token-{calls['count']}",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),
        )

    monkeypatch.setattr(github_app_auth_service, "_exchange_installation_token", fake_exchange)

    first = github_app_auth_service.get_installation_token(42)
    second = github_app_auth_service.get_installation_token(42)

    assert first == "token-1"
    assert second == "token-1"
    assert calls["count"] == 1


def test_installation_token_cache_refreshes_five_minutes_before_expiry(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_exchange(installation_id: int) -> InstallationTokenRecord:
        calls["count"] += 1
        expires = datetime.now(timezone.utc) + timedelta(minutes=(4 if calls["count"] == 1 else 20))
        return InstallationTokenRecord(token=f"token-{calls['count']}", expires_at=expires)

    monkeypatch.setattr(github_app_auth_service, "_exchange_installation_token", fake_exchange)

    first = github_app_auth_service.get_installation_token(7)
    second = github_app_auth_service.get_installation_token(7)

    assert first == "token-1"
    assert second == "token-2"
    assert calls["count"] == 2


def test_worker_run_once_processes_queue_and_completes_check_lifecycle(monkeypatch) -> None:
    monkeypatch.setenv("WORKER_DISABLE_SUBPROCESS_SCAN", "1")
    webhook_worker_service._disable_subprocess_scan = True

    webhook_queue_service.enqueue(
        delivery_id="delivery-77",
        event="pull_request",
        action="opened",
        repository="acme/widget",
        commit_sha="abc123",
        installation_id=123,
        payload={"action": "opened"},
    )

    monkeypatch.setattr(github_app_auth_service, "get_installation_token", lambda installation_id: "inst-token")
    monkeypatch.setattr(
        GithubService,
        "clone_repo_temp_from_github_clone_url",
        lambda github_url: (Path("/tmp/mock"), Path("/tmp/mock/repo")),
    )
    monkeypatch.setattr(GithubService, "cleanup_temp_dir", lambda temp_dir: None)
    monkeypatch.setattr(ScannerService, "scan_repository", lambda self, repo_dir: [])

    lifecycle_calls = {"start": 0, "complete": 0}

    def fake_start_check_run(**kwargs):
        lifecycle_calls["start"] += 1
        assert kwargs["repository"] == "acme/widget"
        assert kwargs["commit_sha"] == "abc123"
        return 998

    def fake_complete_check_run(**kwargs):
        lifecycle_calls["complete"] += 1
        assert kwargs["repository"] == "acme/widget"
        assert kwargs["commit_sha"] == "abc123"
        assert kwargs["conclusion"] == "success"
        return 998

    monkeypatch.setattr(github_check_run_service, "start_check_run", fake_start_check_run)
    monkeypatch.setattr(github_check_run_service, "complete_check_run", fake_complete_check_run)

    response = client.post("/github/worker/run-once")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["delivery_id"] == "delivery-77"
    assert body["check_run_id"] == 998
    assert body["queue_size"] == 0
    assert lifecycle_calls["start"] == 1
    assert lifecycle_calls["complete"] == 1


def test_worker_run_once_is_idle_with_empty_queue() -> None:
    response = client.post("/github/worker/run-once")

    assert response.status_code == 200
    assert response.json()["status"] == "idle"


def test_worker_run_with_retry_succeeds_after_transient_failures(monkeypatch) -> None:
    webhook_queue_service.enqueue(
        delivery_id="delivery-retry-ok",
        event="pull_request",
        action="opened",
        repository="acme/widget",
        commit_sha="abc123",
        installation_id=123,
        payload={"action": "opened"},
    )
    job = webhook_queue_service.dequeue_for_worker(timeout_seconds=1, visibility_timeout_seconds=30)
    assert job is not None

    attempts = {"count": 0}
    sleeps: list[int] = []

    def fake_process(inner_job):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("temporary network error")
        return WorkerRunResult(
            status="completed",
            job_id=inner_job.job_id,
            delivery_id=inner_job.delivery_id,
            repository=inner_job.repository,
            commit_sha=inner_job.commit_sha,
            check_run_id=None,
            message="ok",
            duration_seconds=0.0,
        )

    monkeypatch.setattr(webhook_worker_service, "_process_job", fake_process)
    monkeypatch.setattr("backend.services.webhook_worker_service.time.sleep", lambda seconds: sleeps.append(seconds))

    result = webhook_worker_service._run_with_retry(job)

    assert result.status == "completed"
    assert attempts["count"] == 3
    assert sleeps == [1, 2]


def test_worker_run_with_retry_raises_after_max_retries(monkeypatch) -> None:
    webhook_queue_service.enqueue(
        delivery_id="delivery-retry-fail",
        event="pull_request",
        action="opened",
        repository="acme/widget",
        commit_sha="abc123",
        installation_id=123,
        payload={"action": "opened"},
    )
    job = webhook_queue_service.dequeue_for_worker(timeout_seconds=1, visibility_timeout_seconds=30)
    assert job is not None

    attempts = {"count": 0}
    sleeps: list[int] = []

    def always_fail(_job):
        attempts["count"] += 1
        raise RuntimeError("still failing")

    monkeypatch.setattr(webhook_worker_service, "_process_job", always_fail)
    monkeypatch.setattr("backend.services.webhook_worker_service.time.sleep", lambda seconds: sleeps.append(seconds))

    try:
        webhook_worker_service._run_with_retry(job)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "still failing" in str(exc)

    assert attempts["count"] == MAX_RETRIES
    assert sleeps == [1, 2, 4]
