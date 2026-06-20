from datetime import datetime, timezone

from backend.models.scan_model import AIGuidance, ScanResponse, SecurityIssue
from backend.routes.scan import _apply_plan_view
from backend.services.history_service import HistoryService


def _issue(severity: str, index: int) -> SecurityIssue:
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
            danger="Issue danger",
            real_world_example="Issue example",
            exact_fix="Apply parameterized queries",
        ),
    )


def _scan_with_issues(issues: list[SecurityIssue]) -> ScanResponse:
    return ScanResponse(
        scan_id="scan-1",
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


def test_apply_plan_view_shows_full_report_for_everyone() -> None:
    # Payment removed: every authenticated user sees all findings, nothing locked.
    scan = _scan_with_issues([_issue("HIGH", 1), _issue("LOW", 2), _issue("LOW", 3)])
    viewed = _apply_plan_view(scan)

    assert viewed.is_limited is False
    assert viewed.locked_issue_count == 0
    assert viewed.visible_issue_count == len(scan.issues)
    assert viewed.total_issue_count == len(scan.issues)
    assert viewed.access_tier == "full"
    assert viewed.audit_unlocked is True
    assert viewed.upgrade_message is None


def test_history_cache_is_separated_by_strict_mode() -> None:
    history = HistoryService(ttl_hours=None)
    email = "cache@example.com"
    url = "https://github.com/acme/widget"

    normal_scan = _scan_with_issues([_issue("LOW", 1)]).model_copy(update={"scan_id": "normal"})
    strict_scan = _scan_with_issues([_issue("HIGH", 2), _issue("LOW", 3)]).model_copy(update={"scan_id": "strict"})

    normal_job = history.start_scan_job(email, url, strict_mode=False)
    history.complete_scan_job(email, normal_job, normal_scan)

    strict_job = history.start_scan_job(email, url, strict_mode=True)
    history.complete_scan_job(email, strict_job, strict_scan)

    cached_normal = history.get_cached_report(email, url, strict_mode=False)
    cached_strict = history.get_cached_report(email, url, strict_mode=True)

    assert cached_normal is not None
    assert cached_strict is not None
    assert cached_normal.scan_id == "normal"
    assert cached_strict.scan_id == "strict"
