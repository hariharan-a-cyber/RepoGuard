from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
from threading import Lock
import time
from uuid import uuid4

from backend.services import db


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_UPPER_RE = re.compile(r"[A-Z]")
PASSWORD_LOWER_RE = re.compile(r"[a-z]")
PASSWORD_DIGIT_RE = re.compile(r"\d")
PASSWORD_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
FREE_SCAN_LIMIT_PER_DAY = 3
PBKDF2_ITERATIONS = 210_000


DEFAULT_TOKEN_SECRET = "dev-only-change-me"


@dataclass
class UserRecord:
    email: str
    password_hash: str
    salt: str
    plan: str = "free"


class AuthError(Exception):
    pass


class AuthService:
    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}
        # Backward-compatible attribute used by tests; stores revoked tokens.
        self._sessions: dict[str, int] = {}
        self._scan_events: dict[str, list[datetime]] = {}
        self._audit_unlocks: dict[str, set[str]] = {}
        self._paid_audits: dict[str, set[str]] = {}
        self._lock = Lock()

    def _admin_emails(self) -> set[str]:
        raw = str(os.getenv("ADMIN_EMAILS", "")).strip()
        if not raw:
            return set()
        return {self._normalize_email(item) for item in raw.split(",") if str(item).strip()}

    def _env_flag(self, name: str, default: bool = False) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _lifetime_pro_emails(self) -> set[str]:
        if not self._env_flag("ENABLE_LIFETIME_PRO_OVERRIDE", default=False):
            return set()
        raw = str(os.getenv("LIFETIME_PRO_EMAILS", "")).strip()
        if not raw:
            return set()
        return {self._normalize_email(item) for item in raw.split(",") if str(item).strip()}

    def _apply_lifetime_pro_if_needed_locked(self, user: UserRecord) -> None:
        if user.email in self._lifetime_pro_emails():
            user.plan = "pro"

    def _load_user_from_db_locked(self, normalized_email: str) -> UserRecord | None:
        try:
            row = db.get_user(normalized_email)
        except Exception:
            row = None
        if not row:
            return None

        user = UserRecord(
            email=self._normalize_email(str(row.get("email") or normalized_email)),
            password_hash=str(row.get("password_hash") or ""),
            salt=str(row.get("salt") or ""),
            plan=str(row.get("plan") or "free").strip().lower() or "free",
        )
        self._apply_lifetime_pro_if_needed_locked(user)
        self._users[user.email] = user
        return user

    def _persist_user_locked(self, user: UserRecord) -> None:
        try:
            db.upsert_user(
                email=user.email,
                password_hash=user.password_hash,
                salt=user.salt,
                plan=user.plan,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            # Keep auth available during transient DB outages.
            pass

    def _normalize_email(self, email: str) -> str:
        normalized = email.strip().lower()
        if "@" not in normalized:
            return normalized

        local, domain = normalized.split("@", 1)
        if domain in {"gmail.com", "googlemail.com"}:
            local = local.split("+", 1)[0].replace(".", "")
            domain = "gmail.com"
        return f"{local}@{domain}"

    def _hash_password_legacy(self, password: str, salt: str) -> str:
        digest = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()
        return digest

    def _hash_password(self, password: str, salt: str, iterations: int = PBKDF2_ITERATIONS) -> str:
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        return f"pbkdf2_sha256${iterations}${digest.hex()}"

    def _verify_password_and_upgrade_locked(self, user: UserRecord, password: str) -> bool:
        encoded = str(user.password_hash or "").strip()
        if encoded.startswith("pbkdf2_sha256$"):
            parts = encoded.split("$", 2)
            if len(parts) != 3:
                return False
            try:
                iterations = int(parts[1])
            except ValueError:
                return False
            expected = self._hash_password(password, user.salt, iterations)
            return hmac.compare_digest(expected, encoded)

        # Backward compatibility: verify legacy SHA-256 format, then migrate in place.
        legacy_expected = self._hash_password_legacy(password, user.salt)
        if hmac.compare_digest(legacy_expected, encoded):
            user.password_hash = self._hash_password(password, user.salt)
            self._persist_user_locked(user)
            return True
        return False

    def _token_secret_value(self) -> str:
        return str(os.getenv("TOKEN_SECRET", DEFAULT_TOKEN_SECRET)).strip()

    def _token_secret(self) -> bytes:
        secret = self._token_secret_value()
        return secret.encode("utf-8")

    def is_using_default_token_secret(self) -> bool:
        return self._token_secret_value() == DEFAULT_TOKEN_SECRET

    def _access_token_ttl_seconds(self) -> int:
        raw = str(os.getenv("TOKEN_ACCESS_TTL_SECONDS", os.getenv("TOKEN_TTL_SECONDS", "900"))).strip()
        try:
            ttl = int(raw)
        except ValueError:
            ttl = 900
        return max(300, ttl)

    def _refresh_token_ttl_seconds(self) -> int:
        raw = str(os.getenv("TOKEN_REFRESH_TTL_SECONDS", "2592000")).strip()
        try:
            ttl = int(raw)
        except ValueError:
            ttl = 2592000
        return max(3600, ttl)

    def _b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def _b64url_decode(self, data: str) -> bytes:
        padding = "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode((data + padding).encode("ascii"))

    def _sign(self, message: bytes) -> str:
        signature = hmac.new(self._token_secret(), message, hashlib.sha256).digest()
        return self._b64url_encode(signature)

    def _create_token(self, normalized_email: str, token_type: str, ttl_seconds: int) -> str:
        now = int(time.time())
        payload = {
            "sub": normalized_email,
            "typ": token_type,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": uuid4().hex,
        }
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = self._b64url_encode(payload_json)
        token_body = f"v1.{payload_b64}".encode("ascii")
        signature = self._sign(token_body)
        return f"v1.{payload_b64}.{signature}"

    def _purge_revoked_locked(self) -> None:
        now = int(time.time())
        expired = [token for token, exp in self._sessions.items() if exp <= now]
        for token in expired:
            self._sessions.pop(token, None)

    def _decode_token_payload(self, token: str, expected_type: str) -> dict:
        token_value = str(token or "").strip()
        parts = token_value.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            raise AuthError("Session expired. Please log in again")

        payload_b64 = parts[1]
        provided_signature = parts[2]
        token_body = f"v1.{payload_b64}".encode("ascii")
        expected_signature = self._sign(token_body)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise AuthError("Session expired. Please log in again")

        try:
            payload = json.loads(self._b64url_decode(payload_b64).decode("utf-8"))
        except Exception as exc:
            raise AuthError("Session expired. Please log in again") from exc

        sub = self._normalize_email(str(payload.get("sub") or ""))
        token_type = str(payload.get("typ") or "")
        exp = payload.get("exp")
        if not sub or token_type != expected_type or not isinstance(exp, int):
            raise AuthError("Session expired. Please log in again")
        if exp <= int(time.time()):
            raise AuthError("Session expired. Please log in again")
        return payload

    def _validate_credentials(self, email: str, password: str) -> tuple[str, str]:
        normalized = self._normalize_email(email)
        if not EMAIL_RE.match(normalized):
            raise AuthError("Enter a valid email address")
        if len(password) < 10:
            raise AuthError("Password must be at least 10 characters")
        if not PASSWORD_UPPER_RE.search(password):
            raise AuthError("Password must include at least one uppercase letter")
        if not PASSWORD_LOWER_RE.search(password):
            raise AuthError("Password must include at least one lowercase letter")
        if not PASSWORD_DIGIT_RE.search(password):
            raise AuthError("Password must include at least one number")
        if not PASSWORD_SPECIAL_RE.search(password):
            raise AuthError("Password must include at least one special character")
        return normalized, password

    def _cutoff_24h(self) -> datetime:
        return datetime.now(timezone.utc).replace(microsecond=0)

    def _prune_scan_events_locked(self, normalized_email: str) -> None:
        events = list(self._scan_events.get(normalized_email, []))
        if not events:
            return
        cutoff = self._cutoff_24h().timestamp() - (24 * 60 * 60)
        kept = [item for item in events if item.timestamp() >= cutoff]
        self._scan_events[normalized_email] = kept

    def record_scan(self, email: str) -> None:
        normalized = self._normalize_email(email)
        with self._lock:
            self._prune_scan_events_locked(normalized)
            events = self._scan_events.setdefault(normalized, [])
            now_dt = datetime.now(timezone.utc).replace(microsecond=0)
            events.append(now_dt)
            try:
                db.add_scan_event(normalized, now_dt.isoformat())
            except Exception:
                pass

    def scans_remaining_today(self, email: str, plan: str | None = None) -> int:
        # Payment removed: every authenticated user has unlimited scans.
        return 999999

    def can_scan(self, email: str, plan: str | None = None) -> bool:
        # Payment removed: every authenticated user can always scan.
        return True

    def try_consume_scan(self, email: str, plan: str | None = None) -> bool:
        """Atomically check the daily limit and reserve one scan.

        Returns True if a scan slot was reserved (and recorded), False if the
        free-tier daily limit is already reached. Pro users are always allowed
        and are not metered.
        """
        effective_plan = str(plan or "free").strip().lower()
        normalized = self._normalize_email(email)
        if effective_plan == "pro":
            return True

        with self._lock:
            self._prune_scan_events_locked(normalized)
            used = 0
            cutoff_iso = (self._cutoff_24h() - timedelta(hours=24)).isoformat()
            try:
                used = len(db.get_scan_events_after(normalized, cutoff_iso))
            except Exception:
                used = len(self._scan_events.get(normalized, []))
            if used >= FREE_SCAN_LIMIT_PER_DAY:
                return False

            events = self._scan_events.setdefault(normalized, [])
            now_dt = datetime.now(timezone.utc).replace(microsecond=0)
            events.append(now_dt)
            try:
                db.add_scan_event(normalized, now_dt.isoformat())
            except Exception:
                pass
            return True

    def refund_scan(self, email: str) -> None:
        """Return one reserved scan slot after a terminal scan failure.

        Removes the most recent in-memory scan event. The matching DB row is
        best-effort and intentionally left to the 24h prune window, since the
        in-memory counter is the fast path consulted by try_consume_scan.
        """
        normalized = self._normalize_email(email)
        with self._lock:
            events = self._scan_events.get(normalized)
            if events:
                events.pop()
        try:
            db.delete_latest_scan_event(normalized)
        except Exception:
            pass

    def unlock_audit_scan(self, email: str, scan_id: str) -> None:
        normalized = self._normalize_email(email)
        scan_key = str(scan_id or "").strip()
        if not scan_key:
            raise AuthError("scan_id is required")
        with self._lock:
            unlocked = self._audit_unlocks.setdefault(normalized, set())
            unlocked.add(scan_key)
            try:
                db.add_audit_unlock(normalized, scan_key)
            except Exception:
                pass

    def has_audit_access(self, email: str, scan_id: str) -> bool:
        normalized = self._normalize_email(email)
        scan_key = str(scan_id or "").strip()
        if not scan_key:
            return False
        with self._lock:
            unlocked = self._audit_unlocks.get(normalized, set())
            if scan_key in unlocked:
                return True
        try:
            return scan_key in db.get_audit_unlocks(normalized)
        except Exception:
            return False

    def has_paid_audit(self, email: str, scan_id: str) -> bool:
        normalized = self._normalize_email(email)
        scan_key = str(scan_id or "").strip()
        if not scan_key:
            return False
        with self._lock:
            paid = self._paid_audits.get(normalized, set())
            return scan_key in paid

    def record_paid_audit(self, email: str, scan_id: str) -> None:
        normalized = self._normalize_email(email)
        scan_key = str(scan_id or "").strip()
        if not scan_key:
            raise AuthError("scan_id is required")
        with self._lock:
            paid = self._paid_audits.setdefault(normalized, set())
            paid.add(scan_key)

    def unlocked_scan_count(self, email: str) -> int:
        normalized = self._normalize_email(email)
        db_count = None
        try:
            db_count = len(db.get_audit_unlocks(normalized))
        except Exception:
            db_count = None
        with self._lock:
            mem_count = len(self._audit_unlocks.get(normalized, set()))
        if db_count is None:
            return mem_count
        return max(mem_count, db_count)

    def set_plan(self, email: str, plan: str) -> UserRecord:
        normalized = self._normalize_email(email)
        next_plan = str(plan or "").strip().lower()
        if next_plan not in {"free", "pro"}:
            raise AuthError("Unsupported plan")

        with self._lock:
            user = self._users.get(normalized)
            if user is None:
                user = self._load_user_from_db_locked(normalized)
            if user is None:
                raise AuthError("Account not found. Register first")
            user.plan = next_plan
            self._apply_lifetime_pro_if_needed_locked(user)
            self._persist_user_locked(user)
            try:
                db.set_user_plan(user.email, user.plan)
            except Exception:
                pass
            return user

    def access_token_ttl_seconds(self) -> int:
        return self._access_token_ttl_seconds()

    def refresh_token_ttl_seconds(self) -> int:
        return self._refresh_token_ttl_seconds()

    def _is_revoked_locked(self, token_value: str) -> bool:
        if token_value in self._sessions:
            return True
        try:
            return db.is_token_revoked(token_value)
        except Exception:
            # Keep auth available if DB is temporarily unavailable.
            return False

    def _revoke_token_locked(self, token_value: str, exp: int) -> None:
        self._sessions[token_value] = exp
        try:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
            db.revoke_token(token_value, datetime.now(timezone.utc).isoformat(), expires_at)
        except Exception:
            # DB outage should not break in-memory revocation path.
            pass

    def _create_session_locked(self, normalized_email: str) -> tuple[str, str]:
        self._purge_revoked_locked()
        access_token = self._create_token(normalized_email, "access", self._access_token_ttl_seconds())
        refresh_token = self._create_token(normalized_email, "refresh", self._refresh_token_ttl_seconds())
        return access_token, refresh_token

    def register(self, email: str, password: str) -> tuple[str, str, UserRecord]:
        normalized, raw_password = self._validate_credentials(email, password)
        with self._lock:
            if normalized in self._users or self._load_user_from_db_locked(normalized) is not None:
                raise AuthError("Email already registered")
            salt = uuid4().hex
            record = UserRecord(
                email=normalized,
                password_hash=self._hash_password(raw_password, salt),
                salt=salt,
                plan="free",
            )
            self._apply_lifetime_pro_if_needed_locked(record)
            self._users[normalized] = record
            self._persist_user_locked(record)
            access_token, refresh_token = self._create_session_locked(normalized)
            return access_token, refresh_token, record

    def login(self, email: str, password: str) -> tuple[str, str, UserRecord]:
        normalized, raw_password = self._validate_credentials(email, password)
        with self._lock:
            user = self._users.get(normalized)
            if user is None:
                user = self._load_user_from_db_locked(normalized)
            if user is None:
                raise AuthError("Invalid email or password")
            if not self._verify_password_and_upgrade_locked(user, raw_password):
                raise AuthError("Invalid email or password")
            self._apply_lifetime_pro_if_needed_locked(user)
            self._persist_user_locked(user)
            access_token, refresh_token = self._create_session_locked(normalized)
            return access_token, refresh_token, user

    def login_or_register_google(self, email: str) -> tuple[str, str, UserRecord]:
        normalized = self._normalize_email(email)
        if not EMAIL_RE.match(normalized):
            raise AuthError("Google account email is invalid")

        with self._lock:
            user = self._users.get(normalized)
            if user is None:
                user = self._load_user_from_db_locked(normalized)
            if user is None:
                salt = uuid4().hex
                # Placeholder hash so account remains compatible with existing user model.
                placeholder_password = uuid4().hex
                user = UserRecord(
                    email=normalized,
                    password_hash=self._hash_password(placeholder_password, salt),
                    salt=salt,
                    plan="free",
                )
                self._apply_lifetime_pro_if_needed_locked(user)
                self._users[normalized] = user
            else:
                self._apply_lifetime_pro_if_needed_locked(user)

            self._persist_user_locked(user)

            access_token, refresh_token = self._create_session_locked(normalized)
            return access_token, refresh_token, user

    def refresh_session(self, refresh_token: str) -> tuple[str, str, UserRecord]:
        with self._lock:
            self._purge_revoked_locked()
            token_value = str(refresh_token or "").strip()
            if self._is_revoked_locked(token_value):
                raise AuthError("Session expired. Please log in again")

            payload = self._decode_token_payload(token_value, expected_type="refresh")
            email = self._normalize_email(str(payload.get("sub") or ""))
            user = self._users.get(email)
            if user is None:
                user = self._load_user_from_db_locked(email)
            if user is None:
                raise AuthError("Session expired. Please log in again")

            exp = payload.get("exp")
            if isinstance(exp, int):
                # Rotate refresh token on every refresh call.
                self._revoke_token_locked(token_value, exp)

            self._apply_lifetime_pro_if_needed_locked(user)
            access_token, new_refresh_token = self._create_session_locked(email)
            return access_token, new_refresh_token, user

    def _revoke_if_possible_locked(self, token: str | None, expected_type: str) -> None:
        token_value = str(token or "").strip()
        if not token_value:
            return
        try:
            payload = self._decode_token_payload(token_value, expected_type=expected_type)
        except AuthError:
            return
        exp = payload.get("exp")
        if isinstance(exp, int):
            self._revoke_token_locked(token_value, exp)

    def logout(self, access_token: str | None, refresh_token: str | None = None) -> None:
        with self._lock:
            self._purge_revoked_locked()
            self._revoke_if_possible_locked(access_token, expected_type="access")
            self._revoke_if_possible_locked(refresh_token, expected_type="refresh")

    def get_user_by_token(self, token: str | None) -> UserRecord:
        with self._lock:
            self._purge_revoked_locked()
            token_value = str(token or "").strip()
            if self._is_revoked_locked(token_value):
                raise AuthError("Session expired. Please log in again")

            payload = self._decode_token_payload(token_value, expected_type="access")
            email = self._normalize_email(str(payload.get("sub") or ""))
            user = self._users.get(email)
            if user is None:
                user = self._load_user_from_db_locked(email)
            if user is None:
                raise AuthError("Session expired. Please log in again")
            return user

    def require_admin(self, token: str | None) -> UserRecord:
        user = self.get_user_by_token(token)
        if user.email not in self._admin_emails():
            raise AuthError("Admin access required")
        return user

auth_service = AuthService()
