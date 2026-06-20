import os
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException
from fastapi import Query, Response

from backend.models.scan_model import FeedbackItem, FeedbackRequest, FeedbackResponse
from backend.services.auth_service import AuthError, auth_service
from backend.services.feedback_service import FeedbackRateLimitError, feedback_service
from backend.services.history_service import history_service

router = APIRouter(prefix="/feedback", tags=["feedback"])


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _is_feedback_admin(email: str) -> bool:
    configured = str(os.getenv("FEEDBACK_ADMIN_EMAILS", "")).strip()
    if not configured:
        return False

    allowed = {item.strip().lower() for item in configured.split(",") if item.strip()}
    return str(email or "").strip().lower() in allowed


def _get_authenticated_user(authorization: str | None):
    token = _extract_bearer_token(authorization)
    try:
        return auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _require_feedback_admin(authorization: str | None):
    user = _get_authenticated_user(authorization)
    if not _is_feedback_admin(user.email):
        raise HTTPException(status_code=403, detail="Feedback admin access required")
    return user


@router.post("", response_model=FeedbackResponse)
def submit_feedback(payload: FeedbackRequest, authorization: str | None = Header(default=None)) -> FeedbackResponse:
    user = _get_authenticated_user(authorization)

    scan = history_service.get_scan(user.email, payload.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found for this user")

    try:
        item = feedback_service.submit(user.email, payload)
    except FeedbackRateLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    return FeedbackResponse(item=item)


@router.get("/me", response_model=list[FeedbackItem])
def list_my_feedback(authorization: str | None = Header(default=None)) -> list[FeedbackItem]:
    user = _get_authenticated_user(authorization)

    return feedback_service.list_for_user(user.email)


@router.get("/admin", response_model=list[FeedbackItem])
def list_admin_feedback(
    authorization: str | None = Header(default=None),
    category: str | None = Query(default=None),
    min_rating: int | None = Query(default=None, ge=1, le=5),
    max_rating: int | None = Query(default=None, ge=1, le=5),
    scan_id: str | None = Query(default=None),
    email: str | None = Query(default=None),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[FeedbackItem]:
    _require_feedback_admin(authorization)
    return feedback_service.list_filtered(
        category=category,
        min_rating=min_rating,
        max_rating=max_rating,
        scan_id=scan_id,
        email=email,
        start_at=start_at,
        end_at=end_at,
        limit=limit,
        offset=offset,
    )


@router.get("/admin/export.csv")
def export_admin_feedback_csv(
    authorization: str | None = Header(default=None),
    category: str | None = Query(default=None),
    min_rating: int | None = Query(default=None, ge=1, le=5),
    max_rating: int | None = Query(default=None, ge=1, le=5),
    scan_id: str | None = Query(default=None),
    email: str | None = Query(default=None),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Response:
    _require_feedback_admin(authorization)
    items = feedback_service.list_filtered(
        category=category,
        min_rating=min_rating,
        max_rating=max_rating,
        scan_id=scan_id,
        email=email,
        start_at=start_at,
        end_at=end_at,
        limit=limit,
        offset=offset,
    )
    csv_payload = feedback_service.export_csv(items)
    return Response(
        content=csv_payload,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=feedback-export.csv"},
    )
