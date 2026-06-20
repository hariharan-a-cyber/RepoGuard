from fastapi.testclient import TestClient

from backend.main import app
from backend.routes import auth as auth_route
from backend.services.auth_service import UserRecord, auth_service


client = TestClient(app)


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()
    auth_route._login_attempts.clear()


def test_login_uses_generic_error_for_unknown_accounts() -> None:
    _reset_state()
    response = client.post("/auth/login", json={"email": "missing@example.com", "password": "StrongPass1!"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_legacy_password_hash_migrates_to_pbkdf2_after_successful_login() -> None:
    _reset_state()
    email = "legacy@example.com"
    password = "StrongPass1!"
    salt = "legacy-salt"

    # Seed a legacy SHA-256 password record to verify compatibility migration.
    legacy_hash = auth_service._hash_password_legacy(password, salt)
    auth_service._users[email] = UserRecord(email=email, password_hash=legacy_hash, salt=salt, plan="free")

    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200

    updated = auth_service._users[email]
    assert updated.password_hash.startswith("pbkdf2_sha256$")


def test_register_rate_limit_triggers_after_repeated_failures(monkeypatch) -> None:
    _reset_state()
    monkeypatch.setattr(auth_route, "_LOGIN_RATE_MAX_ATTEMPTS", 2)

    # Duplicate registration keeps failing and should eventually hit rate limit.
    first = client.post("/auth/register", json={"email": "rl@example.com", "password": "StrongPass1!"})
    assert first.status_code == 200

    duplicate_1 = client.post("/auth/register", json={"email": "rl@example.com", "password": "StrongPass1!"})
    assert duplicate_1.status_code == 400

    duplicate_2 = client.post("/auth/register", json={"email": "rl@example.com", "password": "StrongPass1!"})
    assert duplicate_2.status_code == 400

    blocked = client.post("/auth/register", json={"email": "rl@example.com", "password": "StrongPass1!"})
    assert blocked.status_code == 429


def test_refresh_rate_limit_triggers_after_repeated_invalid_tokens(monkeypatch) -> None:
    _reset_state()
    monkeypatch.setattr(auth_route, "_LOGIN_RATE_MAX_ATTEMPTS", 2)

    bad_payload = {"refresh_token": "v1.invalid.invalid"}
    r1 = client.post("/auth/refresh", json=bad_payload)
    assert r1.status_code == 401

    r2 = client.post("/auth/refresh", json=bad_payload)
    assert r2.status_code == 401

    blocked = client.post("/auth/refresh", json=bad_payload)
    assert blocked.status_code == 429
