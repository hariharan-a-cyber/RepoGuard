from pathlib import Path
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from backend.routes.auth import router as auth_router
from backend.routes.feedback import router as feedback_router
from backend.routes.github_app import router as github_app_router
from backend.routes.metrics import router as metrics_router
from backend.routes.scan import router as scan_router
from backend.routes.validation import router as validation_router
from backend.services.auth_service import AuthService
from backend.services.db import init_db, prune_expired_revoked_tokens
from backend.services.queue_client import get_queue_depth, get_worker_count
from backend.services.webhook_queue_service import webhook_queue_service

load_dotenv(override=True)
init_db()
# Bound the revoked-tokens table on boot; expired tokens are self-rejecting
# via signature expiry, so their revocation rows are safe to delete.
try:
    prune_expired_revoked_tokens()
except Exception:
    pass


def _is_production() -> bool:
    return str(os.getenv("ENV", "development")).strip().lower() == "production"


def _required_production_env() -> None:
    if not _is_production():
        return

    webhook_secret = str(os.getenv("GITHUB_APP_WEBHOOK_SECRET", "")).strip()
    if not webhook_secret:
        raise RuntimeError(
            "FATAL: GITHUB_APP_WEBHOOK_SECRET is required in production. "
            "Set this before starting the API."
        )


# Production readiness check: Ensure a strong TOKEN_SECRET is set.
auth_service = AuthService()
if _is_production() and auth_service.is_using_default_token_secret():
    raise RuntimeError(
        "FATAL: TOKEN_SECRET is not set or is using the default insecure value in a production environment. "
        "Please set a strong, unique secret in your .env file or environment variables before starting."
    )

_required_production_env()


def _cors_origins() -> list[str]:
    raw = str(os.getenv("CORS_ORIGINS", "")).strip()
    if not raw:
        return ["http://127.0.0.1:8000", "http://localhost:8000"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]

app = FastAPI(title="GitHub Security Auditor", version="1.0.0")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com https://apis.google.com https://www.gstatic.com https://plausible.io 'unsafe-inline' https://firebasestorage.googleapis.com; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https: https://securetoken.googleapis.com https://identitytoolkit.googleapis.com; "
        "frame-src 'self' https://accounts.google.com https://*.google.com https://*.firebaseapp.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Google sign-in popup/One Tap needs opener access across origins.
    response.headers["Cross-Origin-Opener-Policy"] = "unsafe-none"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if _is_production():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(auth_router)
app.include_router(feedback_router)
app.include_router(github_app_router)
app.include_router(metrics_router)
app.include_router(validation_router)

FRONTEND_DIR = (Path(__file__).resolve().parent.parent / "frontend").resolve()
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "queue_depth": get_queue_depth(),
        "workers_alive": get_worker_count(),
        "inflight": webhook_queue_service.current_inflight(),
    }


@app.get("/")
def home() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html", headers=NO_CACHE_HEADERS)


@app.get("/styles.css")
def styles() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "styles.css", headers=NO_CACHE_HEADERS)


@app.get("/app.js")
def script() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "app.js", headers=NO_CACHE_HEADERS)
