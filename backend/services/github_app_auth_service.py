from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock

import httpx

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    redis = None


class GithubAppAuthError(Exception):
    pass


@dataclass
class InstallationTokenRecord:
    token: str
    expires_at: datetime


class GithubAppAuthService:
    def __init__(self, refresh_before_expiry_seconds: int = 300) -> None:
        self._refresh_before_expiry = max(0, int(refresh_before_expiry_seconds))
        self._cache: dict[int, InstallationTokenRecord] = {}
        self._lock = Lock()
        self._redis = None
        self._prefix = str(os.getenv("GITHUB_INSTALL_TOKEN_KEY_PREFIX", "repoguard:github:installation-token")).strip() or "repoguard:github:installation-token"

        redis_url = str(os.getenv("REDIS_URL", "")).strip()
        if redis_url and redis is not None:
            try:
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    @staticmethod
    def _github_api_base() -> str:
        return str(os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")).strip().rstrip("/")

    @staticmethod
    def _app_id() -> str:
        return str(os.getenv("GITHUB_APP_ID", "")).strip()

    @staticmethod
    def _private_key() -> str:
        return str(
            os.getenv("GITHUB_APP_PRIVATE_KEY", "")
            or os.getenv("GITHUB_PRIVATE_KEY", "")
        ).strip()

    @staticmethod
    def _jwt_override() -> str:
        return str(os.getenv("GITHUB_APP_JWT_OVERRIDE", "")).strip()

    @staticmethod
    def _install_url_override() -> str:
        return str(os.getenv("GITHUB_APP_INSTALL_URL", "")).strip()

    @staticmethod
    def _parse_github_timestamp(value: str) -> datetime:
        text = str(value or "").strip()
        if not text:
            raise GithubAppAuthError("GitHub token response is missing expires_at")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise GithubAppAuthError("Invalid expires_at format in GitHub response") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _cache_hit(self, installation_id: int, now: datetime) -> str | None:
        record = self._cache.get(installation_id)
        if record is None:
            return None
        refresh_boundary = now + timedelta(seconds=self._refresh_before_expiry)
        if record.expires_at <= refresh_boundary:
            return None
        return record.token

    def _redis_key(self, installation_id: int) -> str:
        return f"{self._prefix}:{int(installation_id)}"

    def _redis_cache_hit(self, installation_id: int, now: datetime) -> str | None:
        if self._redis is None:
            return None
        raw = self._redis.get(self._redis_key(installation_id))
        if not raw:
            return None
        try:
            data = json.loads(str(raw))
            token = str(data.get("token") or "").strip()
            expires_at = self._parse_github_timestamp(str(data.get("expires_at") or ""))
        except Exception:
            return None

        refresh_boundary = now + timedelta(seconds=self._refresh_before_expiry)
        if expires_at <= refresh_boundary:
            return None
        return token

    def _cache_store(self, installation_id: int, record: InstallationTokenRecord) -> None:
        self._cache[installation_id] = record
        if self._redis is None:
            return
        ttl = int((record.expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl <= 0:
            return
        payload = json.dumps(
            {
                "token": record.token,
                "expires_at": record.expires_at.isoformat().replace("+00:00", "Z"),
            },
            separators=(",", ":"),
        )
        self._redis.set(self._redis_key(installation_id), payload, ex=ttl)

    def _build_app_jwt(self) -> str:
        override = self._jwt_override()
        if override:
            return override

        app_id = self._app_id()
        private_key = self._private_key()
        if not app_id or not private_key:
            raise GithubAppAuthError("GitHub App credentials are not configured")

        try:
            import jwt  # type: ignore[import-not-found]
        except Exception as exc:
            raise GithubAppAuthError("PyJWT is required for GitHub App auth. Install with pip install PyJWT") from exc

        now = datetime.now(timezone.utc)
        payload = {
            "iat": int((now - timedelta(seconds=30)).timestamp()),
            "exp": int((now + timedelta(minutes=9)).timestamp()),
            "iss": app_id,
        }

        try:
            token = jwt.encode(payload, private_key, algorithm="RS256")
        except Exception as exc:
            raise GithubAppAuthError("Failed to create GitHub App JWT") from exc

        if isinstance(token, bytes):
            return token.decode("utf-8")
        return str(token)

    def _exchange_installation_token(self, installation_id: int) -> InstallationTokenRecord:
        jwt_token = self._build_app_jwt()
        url = f"{self._github_api_base()}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, headers=headers)
        except httpx.HTTPError as exc:
            raise GithubAppAuthError("GitHub token exchange request failed") from exc

        if response.status_code >= 400:
            detail = response.text.strip()[:300]
            raise GithubAppAuthError(f"GitHub token exchange failed: {response.status_code} {detail}")

        data = response.json() if response.content else {}
        token = str(data.get("token") or "").strip()
        if not token:
            raise GithubAppAuthError("GitHub token exchange returned empty token")

        expires_at = self._parse_github_timestamp(str(data.get("expires_at") or ""))
        return InstallationTokenRecord(token=token, expires_at=expires_at)

    def get_install_url(self) -> str:
        override = self._install_url_override()
        if override:
            return override

        jwt_token = self._build_app_jwt()
        url = f"{self._github_api_base()}/app"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise GithubAppAuthError("Failed to fetch GitHub App metadata") from exc

        if response.status_code >= 400:
            detail = response.text.strip()[:300]
            raise GithubAppAuthError(f"GitHub App metadata request failed: {response.status_code} {detail}")

        data = response.json() if response.content else {}
        slug = str(data.get("slug") or "").strip()
        if not slug:
            raise GithubAppAuthError("GitHub App slug is missing; set GITHUB_APP_INSTALL_URL explicitly")
        return f"https://github.com/apps/{slug}/installations/new"

    def get_app_status(self) -> dict[str, object]:
        app_id = self._app_id()
        private_key = self._private_key()
        configured = bool(app_id and private_key)
        status: dict[str, object] = {
            "configured": configured,
            "connected": False,
            "installation_count": 0,
        }

        if not configured:
            return status

        install_url = self._install_url_override()
        if install_url:
            status["install_url"] = install_url

        jwt_token = self._build_app_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(f"{self._github_api_base()}/app/installations", headers=headers)
        except httpx.HTTPError as exc:
            raise GithubAppAuthError("Failed to fetch GitHub App installation status") from exc

        if response.status_code >= 400:
            detail = response.text.strip()[:300]
            raise GithubAppAuthError(f"GitHub App installation status failed: {response.status_code} {detail}")

        data = response.json() if response.content else []
        installations = data if isinstance(data, list) else []
        installation_count = len(installations)
        status.update(
            {
                "connected": installation_count > 0,
                "installation_count": installation_count,
            }
        )
        return status

    def get_installation_token(self, installation_id: int) -> str:
        normalized_id = int(installation_id)
        now = datetime.now(timezone.utc)

        with self._lock:
            cached = self._cache_hit(normalized_id, now)
            if cached:
                return cached

        redis_cached = self._redis_cache_hit(normalized_id, now)
        if redis_cached:
            return redis_cached

        record = self._exchange_installation_token(normalized_id)

        with self._lock:
            self._cache_store(normalized_id, record)
            return record.token

    def reset_for_testing(self) -> None:
        with self._lock:
            self._cache.clear()
        if self._redis is not None:
            for key in self._redis.scan_iter(match=f"{self._prefix}:*"):
                self._redis.delete(key)


github_app_auth_service = GithubAppAuthService()
