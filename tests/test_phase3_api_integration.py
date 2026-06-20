from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.scan_model import AIGuidance, ScanResponse, SecurityIssue
from backend.services.auth_service import auth_service
from backend.services.history_service import history_service


client = TestClient(app)


def _mk_issue(severity: str, index: int) -> SecurityIssue:
    return SecurityIssue(
        title=f"[{severity}] Finding {index}",
        severity=severity,
        file="server.js",
        line=index + 1,
        scanner="regex",
        rule_id=f"regex.{index}",
        message="Security issue",
        category="SQL Injection" if severity == "HIGH" else "Weak Input Validation",
        data_source="user_input",
        usage_context="database",
        evidence="db.query(userInput)",
        confidence=82 if severity == "HIGH" else 61,
        confidence_label="HIGH" if severity == "HIGH" else "MEDIUM",
        exploitability_level="HIGH" if severity == "HIGH" else "MEDIUM",
        source_symbol="req.body.id",
        sink_symbol="db.query",
        propagation_chain=["req.body.id", "queryArg"],
        exploit_scenario=["step one", "step two", "step three"],
        guidance=AIGuidance(
            explanation="Issue explanation",
            danger="Danger details",
            real_world_example="Exploit path",
            exact_fix="Before:\nBAD\n\nAfter:\nGOOD",
        ),
    )


def _mk_scan(scan_id: str) -> ScanResponse:
    issues = [_mk_issue("HIGH", 1), _mk_issue("MEDIUM", 2), _mk_issue("LOW", 3)]
    return ScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        github_url="https://github.com/acme/widget",
        repo_name="widget",
        issue_count=len(issues),
        risk_score=55,
        issues=issues,
        priority_issues=issues[:3],
        file_summary={"server.js": len(issues)},
        score_breakdown={"code_safety": 50, "secrets_management": 90, "input_handling": 45},
        recommendations=["Use parameterized queries."],
    )


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reset_state(tmp_path) -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()

    history_service._items.clear()
    history_service._jobs.clear()
    history_service._repo_cache.clear()


def test_scan_status_returns_full_report_for_authenticated_user(tmp_path) -> None:
    _reset_state(tmp_path)

    register = client.post("/auth/register", json={"email": "phase3-api@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    scan_id = history_service.start_scan_job("phase3-api@example.com", "https://github.com/acme/widget")
    history_service.attach_cached_report_to_job("phase3-api@example.com", scan_id, _mk_scan(scan_id))

    result = client.get(f"/scan/{scan_id}", headers=_auth_header(token))
    assert result.status_code == 200
    report = result.json()["report"]
    # Payment removed: every authenticated user sees the full report immediately.
    assert report["access_tier"] == "full"
    assert report["audit_unlocked"] is True
    assert report["is_limited"] is False
    assert report["locked_issue_count"] == 0
    assert report["visible_issue_count"] == report["total_issue_count"]


