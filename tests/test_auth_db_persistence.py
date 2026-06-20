import pytest

from backend.services import db
from backend.services.auth_service import AuthError, auth_service


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()
    auth_service._paid_audits.clear()
    with db.get_conn() as conn:
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM scan_events")
        conn.execute("DELETE FROM audit_unlocks")
        conn.execute("DELETE FROM revoked_tokens")
        conn.commit()


def test_login_loads_user_from_db_when_memory_is_empty() -> None:
    _reset_state()

    auth_service.register("persist@example.com", "StrongPass1!")
    auth_service._users.clear()

    access_token, refresh_token, user = auth_service.login("persist@example.com", "StrongPass1!")
    assert access_token
    assert refresh_token
    assert user.email == "persist@example.com"


def test_scans_are_unlimited_for_authenticated_users() -> None:
    _reset_state()

    auth_service.register("quota@example.com", "StrongPass1!")
    auth_service.record_scan("quota@example.com")
    auth_service.record_scan("quota@example.com")
    auth_service.record_scan("quota@example.com")

    auth_service._scan_events.clear()

    # Payment removed: scanning is unlimited for every authenticated user.
    assert auth_service.scans_remaining_today("quota@example.com", "free") == 999999
    assert auth_service.can_scan("quota@example.com", "free") is True


def test_access_token_lookup_loads_user_from_db() -> None:
    _reset_state()

    access_token, _, _ = auth_service.register("token-db@example.com", "StrongPass1!")
    auth_service._users.clear()

    user = auth_service.get_user_by_token(access_token)
    assert user.email == "token-db@example.com"

    with db.get_conn() as conn:
        conn.execute("DELETE FROM users WHERE email = ?", ("token-db@example.com",))
        conn.commit()

    auth_service._users.clear()
    with pytest.raises(AuthError):
        auth_service.get_user_by_token(access_token)
