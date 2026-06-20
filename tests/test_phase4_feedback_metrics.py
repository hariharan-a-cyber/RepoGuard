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


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()

    feedback_service._items.clear()
    history_service._items.clear()
    history_service._jobs.clear()
    history_service._repo_cache.clear()
    metrics_service._events.clear()


def _mk_issue() -> SecurityIssue:
    return SecurityIssue(
        title="[HIGH] SQL Injection",
        severity="HIGH",
        file="server.js",
        line=12,
        scanner="regex",
        rule_id="regex.sql",
        message="Potential SQL injection",
        category="SQL Injection",
        data_source="user_input",
        usage_context="database",
        confidence=90,
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
        risk_score=55,
        issues=issues,
        priority_issues=issues,
        file_summary={"server.js": 1},
        score_breakdown={"code_safety": 50, "secrets_management": 90, "input_handling": 45},
    )


def test_feedback_submit_and_list_for_authenticated_user() -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "feedback@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    scan_id = history_service.start_scan_job("feedback@example.com", "https://github.com/acme/repo")
    history_service.attach_cached_report_to_job("feedback@example.com", scan_id, _mk_scan(scan_id))

    submit = client.post(
        "/feedback",
        headers=_auth_header(token),
        json={
            "scan_id": scan_id,
            "rating": 4,
            "category": "general",
            "comment": "The proof block was clear and useful.",
        },
    )
    assert submit.status_code == 200
    payload = submit.json()
    assert payload["status"] == "ok"
    assert payload["item"]["scan_id"] == scan_id
    assert payload["item"]["rating"] == 4

    listed = client.get("/feedback/me", headers=_auth_header(token))
    assert listed.status_code == 200
    entries = listed.json()
    assert len(entries) == 1
    assert entries[0]["category"] == "general"


def test_feedback_rejects_missing_scan_for_user() -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "feedback-missing@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    response = client.post(
        "/feedback",
        headers=_auth_header(token),
        json={
            "scan_id": "missing-scan-id",
            "rating": 4,
            "category": "general",
            "comment": "Valid message",
        },
    )

    assert response.status_code == 404


def test_feedback_rejects_whitespace_only_comment() -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "feedback-trim@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    scan_id = history_service.start_scan_job("feedback-trim@example.com", "https://github.com/acme/repo")
    history_service.attach_cached_report_to_job("feedback-trim@example.com", scan_id, _mk_scan(scan_id))

    response = client.post(
        "/feedback",
        headers=_auth_header(token),
        json={
            "scan_id": scan_id,
            "rating": 5,
            "category": "general",
            "comment": "   ",
        },
    )

    assert response.status_code == 422


def test_feedback_rate_limits_fast_duplicate_submit() -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "feedback-rate@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    scan_id = history_service.start_scan_job("feedback-rate@example.com", "https://github.com/acme/repo")
    history_service.attach_cached_report_to_job("feedback-rate@example.com", scan_id, _mk_scan(scan_id))

    payload = {
        "scan_id": scan_id,
        "rating": 5,
        "category": "general",
        "comment": "Helpful output",
    }
    first = client.post("/feedback", headers=_auth_header(token), json=payload)
    assert first.status_code == 200

    second = client.post("/feedback", headers=_auth_header(token), json=payload)
    assert second.status_code == 429


def test_metrics_endpoints_return_user_and_cohort_counts(monkeypatch) -> None:
    _reset_state()
    monkeypatch.setenv("ADMIN_EMAILS", "metrics@example.com")

    register = client.post("/auth/register", json={"email": "metrics@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    metrics_service.record(email="metrics@example.com", event="scan_started", scan_id="scan-1")
    metrics_service.record(email="metrics@example.com", event="scan_completed", scan_id="scan-1")
    user_metrics = client.get("/metrics/me", headers=_auth_header(token))
    assert user_metrics.status_code == 200
    user_payload = user_metrics.json()
    assert user_payload["email"] == "metrics@example.com"
    assert user_payload["scans_started"] == 1
    assert user_payload["scans_completed"] == 1
    # Cohort metrics are admin-only after the security hardening fix.
    cohort_metrics = client.get("/metrics/cohort", headers=_auth_header(token))
    assert cohort_metrics.status_code == 200
    cohort_payload = cohort_metrics.json()
    assert cohort_payload["total_events"] >= 2
    assert cohort_payload["unique_users"] >= 1
