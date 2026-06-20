from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from backend.services.github_app_auth_service import GithubAppAuthError, github_app_auth_service
from backend.services.auth_service import AuthError, auth_service
from backend.services.github_webhook_service import (
    WebhookSignatureError,
    verify_webhook_signature,
    webhook_idempotency_service,
)
from backend.services.webhook_worker_service import webhook_worker_service
from backend.services.webhook_queue_service import webhook_queue_service


router = APIRouter(prefix="/github", tags=["github-app"])

_ALLOWED_PR_ACTIONS = {"opened", "synchronize", "reopened"}


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


@router.get("/app/install-url")
def github_app_install_url() -> dict[str, str]:
    try:
        install_url = github_app_auth_service.get_install_url()
    except GithubAppAuthError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"install_url": install_url}


@router.get("/app/status")
def github_app_status() -> dict[str, object]:
    try:
        return github_app_auth_service.get_app_status()
    except GithubAppAuthError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _extract_installation_id(payload: dict[str, Any]) -> int | None:
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        return None
    value = installation.get("id")
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> dict[str, Any]:
    # Enqueue-only webhook handler with inflight-aware backpressure.
    if webhook_queue_service.is_overloaded():
        return {"status": "busy"}

    payload_bytes = await request.body()
    try:
        verify_webhook_signature(payload_bytes, x_hub_signature_256)
    except WebhookSignatureError as exc:
        detail = str(exc)
        status = 503 if "not configured" in detail.lower() else 401
        raise HTTPException(status_code=status, detail=detail) from exc

    delivery_id = str(x_github_delivery or "").strip()
    if not delivery_id:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Delivery header")

    event = str(x_github_event or "").strip().lower()
    if event != "pull_request":
        return {"status": "ignored", "reason": "unsupported_event", "delivery_id": delivery_id}

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = str(payload.get("action") or "").strip().lower()
    if action not in _ALLOWED_PR_ACTIONS:
        return {"status": "ignored", "reason": "unsupported_action", "delivery_id": delivery_id}

    if not webhook_idempotency_service.mark_if_new(delivery_id):
        return {"status": "duplicate", "delivery_id": delivery_id}

    repository = ""
    repo_obj = payload.get("repository")
    if isinstance(repo_obj, dict):
        repository = str(repo_obj.get("full_name") or "").strip()

    pull_request = payload.get("pull_request")
    commit_sha = ""
    if isinstance(pull_request, dict):
        head = pull_request.get("head")
        if isinstance(head, dict):
            commit_sha = str(head.get("sha") or "").strip()

    installation_id = _extract_installation_id(payload)

    job = webhook_queue_service.enqueue(
        delivery_id=delivery_id,
        event=event,
        action=action,
        repository=repository,
        commit_sha=commit_sha,
        installation_id=installation_id,
        payload=payload,
    )

    return {
        "status": "accepted",
        "delivery_id": delivery_id,
        "job_id": job.job_id,
        "queue_size": webhook_queue_service.size(),
    }


@router.get("/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    item = webhook_queue_service.get_job_status(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return item


@router.post("/worker/run-once")
def run_worker_once(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.require_admin(token)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    result = webhook_worker_service.process_next_job()
    if result is None:
        return {"status": "idle", "queue_size": webhook_queue_service.size()}

    metadata = {
        "repo": result.repository,
        "commit": result.commit_sha,
        "duration_seconds": float(result.duration_seconds or 0.0),
    }
    if result.status in {"completed", "skipped"}:
        webhook_queue_service.mark_done(result.job_id, metadata=metadata)
    elif result.status == "failed":
        webhook_queue_service.mark_failed(
            result.job_id,
            result.message,
            metadata={
                **metadata,
                "failure_reason": result.failure_type or result.message,
            },
        )

    return {
        "status": result.status,
        "delivery_id": result.delivery_id,
        "repository": result.repository,
        "commit_sha": result.commit_sha,
        "check_run_id": result.check_run_id,
        "message": result.message,
        "queue_size": webhook_queue_service.size(),
    }
