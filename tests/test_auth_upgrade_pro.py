from uuid import uuid4

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.auth_service import auth_service


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()


def test_upgrade_pro_test_endpoint_is_not_exposed() -> None:
    _reset_state()
    email = f"pro-test-{uuid4().hex[:12]}@example.com"

    register = client.post("/auth/register", json={"email": email, "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    # The test-only pro upgrade endpoint must not exist in the shipped app.
    upgrade = client.post("/auth/upgrade-pro-test", headers=_auth_header(token))
    assert upgrade.status_code == 404

    # Payment removed: every authenticated user can always scan.
    assert auth_service.can_scan(email, "free") is True
