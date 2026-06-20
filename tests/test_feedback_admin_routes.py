from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.scan_model import AIGuidance, ScanResponse, SecurityIssue
from backend.services.auth_service import auth_service
from backend.services.feedback_service import feedback_service
from backend.services.history_service import history_service
from backend.services.metrics_service import metrics_service


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reset_state(tmp_path) -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()

    feedback_service._items.clear()
    feedback_service._store_path = tmp_path / "feedback-test.json"

    history_service._items.clear()
    history_service._jobs.clear()
    history_service._repo_cache.clear()

    metrics_service._events.clear()


def _register(email: str) -> str:
    register = client.post("/auth/register", json={"email": email, "password": "StrongPass1!"})
    assert register.status_code == 200
    return register.json()["token"]


def _mk_issue() -> SecurityIssue:
    return SecurityIssue(
        title="[HIGH] SQL Injection",
        severity="HIGH",
        file="server.js",
        line=7,
        scanner="regex",
        rule_id="regex.sql",
        message="Potential SQL injection",
        category="SQL Injection",
        data_source="user_input",
        usage_context="database",
        confidence=91,
        confidence_label="HIGH",
        guidance=AIGuidance(
            explanation="Issue explanation",
            danger="Issue danger",
            real_world_example="Issue example",
            exact_fix="Before:\nold\n\nAfter:\nnew",
        ),
    )


def _mk_scan(scan_id: str) -> ScanResponse:
    issues = [_mk_issue()]
    return ScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        github_url="https://github.com/acme/repo",
        repo_name="repo",
        issue_count=1,
        risk_score=52,
        issues=issues,
        priority_issues=issues,
        file_summary={"server.js": 1},
        score_breakdown={"code_safety": 50, "secrets_management": 90, "input_handling": 45},
    )


def _attach_scan(email: str) -> str:
    scan_id = history_service.start_scan_job(email, "https://github.com/acme/repo")
    history_service.attach_cached_report_to_job(email, scan_id, _mk_scan(scan_id))
    return scan_id


def test_feedback_admin_list_and_csv_export(tmp_path, monkeypatch) -> None:
    _reset_state(tmp_path)
    monkeypatch.setenv("FEEDBACK_ADMIN_EMAILS", "admin@example.com")

    admin_token = _register("admin@example.com")
    user_a_token = _register("user-a@example.com")
    user_b_token = _register("user-b@example.com")

    scan_a = _attach_scan("user-a@example.com")
    scan_b = _attach_scan("user-b@example.com")

    first = client.post(
        "/feedback",
        headers=_auth_header(user_a_token),
        json={
            "scan_id": scan_a,
            "rating": 4,
            "category": "general",
            "comment": "General feedback",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/feedback",
        headers=_auth_header(user_b_token),
        json={
            "scan_id": scan_b,
            "rating": 5,
            "category": "missing",
            "comment": "Missed one issue",
        },
    )
    assert second.status_code == 200

    filtered = client.get("/feedback/admin?category=missing", headers=_auth_header(admin_token))
    assert filtered.status_code == 200
    items = filtered.json()
    assert len(items) == 1
    assert items[0]["category"] == "missing"

    exported = client.get("/feedback/admin/export.csv?category=missing", headers=_auth_header(admin_token))
    assert exported.status_code == 200
    assert exported.headers.get("content-type", "").startswith("text/csv")
    assert "feedback_id,email,scan_id,rating,category,comment,issue_id,created_at" in exported.text
    assert "Missed one issue" in exported.text


def test_feedback_admin_routes_require_admin_access(tmp_path, monkeypatch) -> None:
    _reset_state(tmp_path)
    monkeypatch.setenv("FEEDBACK_ADMIN_EMAILS", "admin@example.com")

    user_token = _register("non-admin@example.com")

    list_response = client.get("/feedback/admin", headers=_auth_header(user_token))
    assert list_response.status_code == 403

    export_response = client.get("/feedback/admin/export.csv", headers=_auth_header(user_token))
    assert export_response.status_code == 403
