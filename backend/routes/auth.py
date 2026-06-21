import os
from threading import Lock
import time

from fastapi import APIRouter, Cookie, Header, HTTPException, Request, Response

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    redis = None

from backend.models.scan_model import (
    AuthMeResponse,
    AuthLogoutRequest,
    AuthRefreshRequest,
    AuthSessionResponse,
    FirebaseConfigResponse,
    FirebaseSignInRequest,
    GoogleOneTapConfigResponse,
    GoogleOneTapRequest,
    UserAuthRequest,
)
from backend.services.auth_service import AuthError, auth_service
from backend.services.history_service import history_service
from backend.services.metrics_service import metrics_service

router = APIRouter(prefix="/auth", tags=["auth"])

_LOGIN_RATE_WINDOW_SECONDS = 15 * 60
_LOGIN_RATE_MAX_ATTEMPTS = 10
_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = Lock()
_REFRESH_COOKIE_NAME = str(os.getenv("REFRESH_TOKEN_COOKIE_NAME", "repoguard_refresh_token")).strip() or "repoguard_refresh_token"
_RATE_LIMIT_PREFIX = str(os.getenv("AUTH_RATE_LIMIT_KEY_PREFIX", "repoguard:auth:ratelimit")).strip() or "repoguard:auth:ratelimit"
_rate_limit_redis = None

redis_url = str(os.getenv("REDIS_URL", "")).strip()
if redis_url and redis is not None:
    try:
        _rate_limit_redis = redis.Redis.from_url(redis_url, decode_responses=True)
        _rate_limit_redis.ping()
    except Exception:
        _rate_limit_redis = None


def _google_client_id() -> str:
    candidate_keys = (
        "GOOGLE_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_WEB_CLIENT_ID",
    )
    for key in candidate_keys:
        value = str(os.getenv(key, "")).strip().strip('"').strip("'")
        if value:
            return value
    return ""


def _is_production() -> bool:
    return str(os.getenv("ENV", "development")).strip().lower() == "production"


def _verify_google_credential(credential: str, client_id: str) -> str:
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except Exception as exc:  # pragma: no cover - import fallback
        raise HTTPException(status_code=503, detail="Google auth dependency is not installed") from exc

    try:
        payload = google_id_token.verify_oauth2_token(credential, google_requests.Request(), audience=client_id)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Google credential") from exc

    issuer = str(payload.get("iss") or "")
    if issuer not in {"accounts.google.com", "https://accounts.google.com"}:
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    verified_email = str(payload.get("email") or "").strip().lower()
    if not verified_email:
        raise HTTPException(status_code=401, detail="Google account email is missing")
    return verified_email


_firebase_admin_app = None
_firebase_admin_lock = Lock()


def _firebase_project_id() -> str:
    return str(os.getenv("FIREBASE_PROJECT_ID", "")).strip()


def _get_firebase_admin_app():
    global _firebase_admin_app
    if _firebase_admin_app is not None:
        return _firebase_admin_app
    with _firebase_admin_lock:
        if _firebase_admin_app is not None:
            return _firebase_admin_app
        project_id = _firebase_project_id()
        if not project_id:
            return None
        try:
            import firebase_admin
            from firebase_admin import credentials as fb_credentials
            sa_path = str(os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")).strip()
            if sa_path:
                cred = fb_credentials.Certificate(sa_path)
            else:
                cred = fb_credentials.ApplicationDefault()
            _firebase_admin_app = firebase_admin.initialize_app(cred, {"projectId": project_id})
        except Exception:
            _firebase_admin_app = None
    return _firebase_admin_app


def _verify_firebase_id_token(id_token: str) -> str:
    project_id = _firebase_project_id()
    if not project_id or not id_token:
        raise HTTPException(status_code=503, detail="Firebase not configured")

    # Try firebase-admin SDK first
    app = _get_firebase_admin_app()
    if app is not None:
        try:
            from firebase_admin import auth as fb_auth
            decoded = fb_auth.verify_id_token(id_token, app=app)
            email = str(decoded.get("email") or "").strip().lower()
            if email:
                return email
        except Exception:
            pass

    # Fallback: verify Firebase JWT using Google's public key endpoint
    try:
        import jwt as pyjwt
        import httpx as http_req
        resp = http_req.get(
            "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
            timeout=5,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Could not fetch Firebase public keys")
        from cryptography import x509 as _x509
        from cryptography.hazmat.backends import default_backend as _default_backend
        for cert_pem in resp.json().values():
            try:
                cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode(), _default_backend())
                public_key = cert_obj.public_key()
                payload = pyjwt.decode(
                    id_token,
                    public_key,
                    algorithms=["RS256"],
                    audience=project_id,
                    options={"verify_iss": False},
                )
                iss = str(payload.get("iss") or "")
                if iss != f"https://securetoken.google.com/{project_id}":
                    continue
                email = str(payload.get("email") or "").strip().lower()
                if email:
                    return email
            except Exception:
                continue
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Firebase token verification failed") from exc

    raise HTTPException(status_code=401, detail="Invalid Firebase ID token")


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _client_ip(request: Request) -> str:
    forwarded_for = str(request.headers.get("x-forwarded-for", "")).strip()
    if forwarded_for:
        first = forwarded_for.split(",", 1)[0].strip()
        if first:
            return first
    client = request.client
    if client and client.host:
        return str(client.host)
    return "unknown"


def _rate_limit_key(request: Request, subject: str) -> str:
    return f"{_client_ip(request)}|{str(subject or '').strip().lower()}"


def _prune_attempts_locked(now: float, key: str) -> list[float]:
    attempts = [t for t in _login_attempts.get(key, []) if (now - t) <= _LOGIN_RATE_WINDOW_SECONDS]
    if attempts:
        _login_attempts[key] = attempts
    else:
        _login_attempts.pop(key, None)
    return attempts


def _assert_not_rate_limited(key: str) -> None:
    if _rate_limit_redis is not None:
        try:
            redis_key = f"{_RATE_LIMIT_PREFIX}:{key}"
            current = _rate_limit_redis.get(redis_key)
            attempts = int(str(current or "0"))
            if attempts >= _LOGIN_RATE_MAX_ATTEMPTS:
                raise HTTPException(status_code=429, detail="Too many login attempts. Try again later")
            return
        except HTTPException:
            raise
        except Exception:
            # Fall back to in-memory limiting when Redis is unavailable.
            pass

    now = time.time()
    with _login_attempts_lock:
        attempts = _prune_attempts_locked(now, key)
        if len(attempts) >= _LOGIN_RATE_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later")


def _record_failed_attempt(key: str) -> None:
    if _rate_limit_redis is not None:
        try:
            redis_key = f"{_RATE_LIMIT_PREFIX}:{key}"
            current = _rate_limit_redis.incr(redis_key)
            if current == 1:
                _rate_limit_redis.expire(redis_key, _LOGIN_RATE_WINDOW_SECONDS)
            return
        except Exception:
            # Fall back to in-memory limiting when Redis is unavailable.
            pass

    now = time.time()
    with _login_attempts_lock:
        attempts = _prune_attempts_locked(now, key)
        attempts.append(now)
        _login_attempts[key] = attempts


def _clear_failed_attempts(key: str) -> None:
    if _rate_limit_redis is not None:
        try:
            _rate_limit_redis.delete(f"{_RATE_LIMIT_PREFIX}:{key}")
            return
        except Exception:
            # Fall back to in-memory cleanup when Redis is unavailable.
            pass

    with _login_attempts_lock:
        _login_attempts.pop(key, None)


def _is_secure_cookie_context(request: Request) -> bool:
    if _is_production():
        return True
    forwarded_proto = str(request.headers.get("x-forwarded-proto", "")).strip().lower()
    if forwarded_proto == "https":
        return True
    return str(request.url.scheme).strip().lower() == "https"


def _set_refresh_cookie(response: Response, refresh_token: str, request: Request) -> None:
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=_is_secure_cookie_context(request),
        samesite="lax",
        max_age=auth_service.refresh_token_ttl_seconds(),
        path="/auth",
    )


def _clear_refresh_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=_REFRESH_COOKIE_NAME,
        httponly=True,
        secure=_is_secure_cookie_context(request),
        samesite="lax",
        path="/auth",
    )


@router.post("/register", response_model=AuthSessionResponse)
def register(payload: UserAuthRequest, request: Request, response: Response) -> AuthSessionResponse:
    limit_key = _rate_limit_key(request, f"register:{payload.email}")
    _assert_not_rate_limited(limit_key)

    try:
        access_token, refresh_token, user = auth_service.register(payload.email, payload.password)
    except AuthError as exc:
        _record_failed_attempt(limit_key)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _clear_failed_attempts(limit_key)
    _set_refresh_cookie(response, refresh_token, request)

    return AuthSessionResponse(
        token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds(),
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )


@router.post("/login", response_model=AuthSessionResponse)
def login(payload: UserAuthRequest, request: Request, response: Response) -> AuthSessionResponse:
    limit_key = _rate_limit_key(request, f"login:{payload.email}")
    _assert_not_rate_limited(limit_key)

    try:
        access_token, refresh_token, user = auth_service.login(payload.email, payload.password)
    except AuthError as exc:
        _record_failed_attempt(limit_key)
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    _clear_failed_attempts(limit_key)
    _set_refresh_cookie(response, refresh_token, request)

    return AuthSessionResponse(
        token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds(),
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )


@router.get("/google/config", response_model=GoogleOneTapConfigResponse)
def google_one_tap_config() -> GoogleOneTapConfigResponse:
    client_id = _google_client_id()
    if not client_id:
        return GoogleOneTapConfigResponse(enabled=False, client_id=None)
    return GoogleOneTapConfigResponse(enabled=True, client_id=client_id)


@router.post("/google/one-tap", response_model=AuthSessionResponse)
def google_one_tap_login(payload: GoogleOneTapRequest, request: Request, response: Response) -> AuthSessionResponse:
    client_id = _google_client_id()
    if not client_id:
        raise HTTPException(status_code=503, detail="Google One Tap is not configured")

    verified_email = _verify_google_credential(payload.credential, client_id)
    try:
        access_token, refresh_token, user = auth_service.login_or_register_google(verified_email)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    _set_refresh_cookie(response, refresh_token, request)

    return AuthSessionResponse(
        token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds(),
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )


@router.post("/refresh", response_model=AuthSessionResponse)
def refresh_session(
    payload: AuthRefreshRequest | None,
    request: Request,
    response: Response,
    refresh_cookie_token: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
) -> AuthSessionResponse:
    incoming_refresh_token = ""
    if payload and payload.refresh_token:
        incoming_refresh_token = str(payload.refresh_token).strip()
    if not incoming_refresh_token:
        incoming_refresh_token = str(refresh_cookie_token or "").strip()
    if not incoming_refresh_token:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again")

    token_prefix = incoming_refresh_token[:24]
    limit_key = _rate_limit_key(request, f"refresh:{token_prefix}")
    _assert_not_rate_limited(limit_key)

    try:
        access_token, refresh_token, user = auth_service.refresh_session(incoming_refresh_token)
    except AuthError as exc:
        _record_failed_attempt(limit_key)
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    _clear_failed_attempts(limit_key)
    _set_refresh_cookie(response, refresh_token, request)

    return AuthSessionResponse(
        token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds(),
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    payload: AuthLogoutRequest | None = None,
    authorization: str | None = Header(default=None),
    refresh_cookie_token: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
) -> dict[str, str]:
    token = _extract_bearer_token(authorization)
    candidate_refresh = payload.refresh_token if payload else None
    if not candidate_refresh:
        candidate_refresh = refresh_cookie_token
    auth_service.logout(token, candidate_refresh)
    _clear_refresh_cookie(response, request)
    return {"status": "ok"}


@router.get("/firebase/config", response_model=FirebaseConfigResponse)
def firebase_config() -> FirebaseConfigResponse:
    api_key = str(os.getenv("FIREBASE_API_KEY", "")).strip()
    project_id = _firebase_project_id()
    if not api_key or not project_id:
        return FirebaseConfigResponse(enabled=False)
    auth_domain = str(os.getenv("FIREBASE_AUTH_DOMAIN", f"{project_id}.firebaseapp.com")).strip()
    app_id = str(os.getenv("FIREBASE_APP_ID", "")).strip()
    return FirebaseConfigResponse(
        enabled=True,
        apiKey=api_key,
        authDomain=auth_domain,
        projectId=project_id,
        appId=app_id or None,
    )


@router.post("/firebase/signin", response_model=AuthSessionResponse)
def firebase_signin(payload: FirebaseSignInRequest, request: Request, response: Response) -> AuthSessionResponse:
    verified_email = _verify_firebase_id_token(payload.idToken)
    try:
        access_token, refresh_token, user = auth_service.login_or_register_google(verified_email)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    _set_refresh_cookie(response, refresh_token, request)
    return AuthSessionResponse(
        token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds(),
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )


@router.get("/me", response_model=AuthMeResponse)
def me(authorization: str | None = Header(default=None)) -> AuthMeResponse:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return AuthMeResponse(
        email=user.email,
        plan=user.plan,
        scans_remaining_today=auth_service.scans_remaining_today(user.email, user.plan),
        unlocked_scan_count=auth_service.unlocked_scan_count(user.email),
    )



