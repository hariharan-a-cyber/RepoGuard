from fastapi.testclient import TestClient

from backend.main import app
from backend.services.auth_service import auth_service


client = TestClient(app)


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()


def test_google_config_disabled_when_client_id_missing(monkeypatch) -> None:
    from backend.routes import auth as auth_route

    monkeypatch.setattr(auth_route, "_google_client_id", lambda: "")
    response = client.get("/auth/google/config")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert payload["client_id"] is None


def test_google_config_enabled_with_alternate_env_key(monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.setenv("GOOGLE_WEB_CLIENT_ID", "  'deploy-client-id.apps.googleusercontent.com'  ")

    response = client.get("/auth/google/config")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["client_id"] == "deploy-client-id.apps.googleusercontent.com"


def test_google_one_tap_login_registers_or_logs_in(monkeypatch) -> None:
    from backend.routes import auth as auth_route

    _reset_state()
    monkeypatch.setattr(auth_route, "_google_client_id", lambda: "test-google-client-id")

    monkeypatch.setattr(auth_route, "_verify_google_credential", lambda credential, client_id: "user@yourdomain.com")

    response = client.post("/auth/google/one-tap", json={"credential": "mock.google.jwt.token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "user@yourdomain.com"
    assert payload["plan"] == "free"
    assert payload["token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {payload['token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "user@yourdomain.com"


def test_google_one_tap_applies_lifetime_pro_for_gmail_alias(monkeypatch) -> None:
    from backend.routes import auth as auth_route

    _reset_state()
    monkeypatch.setattr(auth_route, "_google_client_id", lambda: "test-google-client-id")
    monkeypatch.setattr(auth_route, "_verify_google_credential", lambda credential, client_id: "My.Name+promo@googlemail.com")
    monkeypatch.setenv("ENABLE_LIFETIME_PRO_OVERRIDE", "true")
    monkeypatch.setenv("LIFETIME_PRO_EMAILS", "myname@gmail.com")

    response = client.post("/auth/google/one-tap", json={"credential": "mock.google.jwt.token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "myname@gmail.com"
    assert payload["plan"] == "pro"
