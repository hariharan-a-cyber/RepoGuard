from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse

from backend.models.scan_model import AnalyticsSummaryResponse, CohortMetricsResponse, UserMetricsResponse
from backend.services.analytics_service import analytics_service
from backend.services.auth_service import AuthError, auth_service
from backend.services.metrics_service import metrics_service

router = APIRouter(prefix="/metrics", tags=["metrics"])


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


@router.get("/me", response_model=UserMetricsResponse)
def my_metrics(authorization: str | None = Header(default=None)) -> UserMetricsResponse:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return metrics_service.user_summary(user.email)


@router.get("/cohort", response_model=CohortMetricsResponse)
def cohort_metrics(authorization: str | None = Header(default=None)) -> CohortMetricsResponse:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.require_admin(token)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return metrics_service.cohort_summary()


@router.get("/export.json", response_model=AnalyticsSummaryResponse)
def export_metrics_json(authorization: str | None = Header(default=None)) -> AnalyticsSummaryResponse:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.require_admin(token)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return analytics_service.summary()


@router.get("/export.csv", response_class=PlainTextResponse)
def export_metrics_csv(authorization: str | None = Header(default=None)) -> PlainTextResponse:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.require_admin(token)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    csv_data = analytics_service.export_csv()
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="repoguard-kpi-export.csv"'},
    )
