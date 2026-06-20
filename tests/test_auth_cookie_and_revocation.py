import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services import db
from backend.services.auth_service import AuthError, auth_service


client = TestClient(app)


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()
    with db.get_conn() as conn:
        conn.execute("DELETE FROM revoked_tokens")
        conn.commit()


def test_register_sets_http_only_refresh_cookie() -> None:
    _reset_state()
    response = client.post(
        "/auth/register",
        json={"email": "cookie@example.com", "password": "StrongPass1!"},
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] == ""

    set_cookie = response.headers.get("set-cookie", "")
    assert "repoguard_refresh_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_refresh_uses_cookie_when_body_token_missing() -> None:
    _reset_state()
    register = client.post(
        "/auth/register",
        json={"email": "refresh-cookie@example.com", "password": "StrongPass1!"},
    )
    assert register.status_code == 200

    refreshed = client.post("/auth/refresh", json={})
    assert refreshed.status_code == 200
    assert refreshed.json()["token"]


def test_refresh_revocation_still_blocks_after_in_memory_state_cleared() -> None:
    _reset_state()
    _, refresh_token, _ = auth_service.register("revoked@example.com", "StrongPass1!")
    auth_service.logout(None, refresh_token)

    # Simulate process restart losing in-memory revocation map.
    auth_service._sessions.clear()

    with pytest.raises(AuthError):
        auth_service.refresh_session(refresh_token)
