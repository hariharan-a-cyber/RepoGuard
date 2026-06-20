from fastapi import APIRouter, Header, HTTPException, Query

from backend.models.scan_model import (
    ValidationLatestArtifactResponse,
    ValidationRunRequest,
    ValidationRunResponse,
)
from backend.services.auth_service import AuthError, auth_service
from backend.services.validation_harness_service import ValidationHarnessError, validation_harness_service

router = APIRouter(prefix="/validation", tags=["validation"])


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


@router.post("/run", response_model=ValidationRunResponse)
def run_validation(payload: ValidationRunRequest, authorization: str | None = Header(default=None)) -> ValidationRunResponse:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    try:
        manifest_id = str(payload.manifest_id or "").strip()
        manifest_path = str(payload.manifest_path or "").strip()
        output_dir = str(payload.output_dir or "").strip() or None

        if manifest_id:
            return validation_harness_service.run_manifest(manifest_id=manifest_id)
        if manifest_path:
            return validation_harness_service.run_manifest_path(manifest_path=manifest_path, output_dir=output_dir)
        raise ValidationHarnessError("Either manifest_id or manifest_path is required")
    except ValidationHarnessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/latest", response_model=ValidationLatestArtifactResponse)
def latest_validation_artifact(
    authorization: str | None = Header(default=None),
    manifest_id: str | None = Query(default=None),
    output_dir: str | None = Query(default=None),
) -> ValidationLatestArtifactResponse:
    token = _extract_bearer_token(authorization)
    try:
        auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    payload = validation_harness_service.latest_artifact(manifest_id=manifest_id, output_dir=output_dir)
    if payload is None:
        raise HTTPException(status_code=404, detail="No validation artifacts found")

    try:
        return ValidationLatestArtifactResponse(
            artifact_path=str(payload.get("artifact_path") or ""),
            run_id=str(payload.get("run_id") or ""),
            generated_at=payload.get("generated_at"),
            manifest_path=str(payload.get("manifest_path") or ""),
            total_repos=int(payload.get("total_repos", 0)),
            passed_repos=int(payload.get("passed_repos", 0)),
            failed_repos=int(payload.get("failed_repos", 0)),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid validation artifact payload: {exc}") from exc
