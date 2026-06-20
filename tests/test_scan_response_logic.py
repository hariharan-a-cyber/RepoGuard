from datetime import datetime, timezone

from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.models.scan_model import ScanResponse
from backend.routes.scan import (
    _complexity_score,
    _confidence_key,
    _exploitability_priority_key,
    _aggregate_risk_explainer,
    _aggregate_risk_label,
    _attach_exploit_scenarios,
    _build_file_summary,
    _coverage_state,
    _display_risk_score,
    _limit_improvement_display,
    _merge_duplicate_issues,
    _popularity_key,
    _priority_key,
    _recommendations,
    _repo_name_from_url,
    _score_breakdown,
    _select_ai_candidates,
    _upgrade_message,
)
from backend.services.scanner_service import ScannerService


def _issue(severity: str) -> SecurityIssue:
    category = "Weak Input Validation"
    if severity == "HIGH":
        category = "SQL Injection"
    if severity == "LOW":
        category = "Flask Debug Mode Enabled"
    if severity == "INFO":
        category = "Unused Import Hygiene"
    return SecurityIssue(
        title=f"[{severity}] {category}",
        severity=severity,
        file="app.py",
        line=10,
        scanner="regex",
        rule_id="regex.test",
        message="test",
        category=category,
        data_source="internal",
        usage_context="unknown",
        evidence="x",
        guidance=AIGuidance(
            explanation="x",
            danger="y",
            real_world_example="z",
            exact_fix="Before:\nold\n\nAfter:\nnew",
        ),
    )


def test_display_risk_score_is_100_when_no_issues() -> None:
    scanner = ScannerService()
    assert _display_risk_score(scanner, []) == 100


def test_display_risk_score_stays_high_for_low_only_findings() -> None:
    scanner = ScannerService()
    issues = [_issue("LOW"), _issue("LOW"), _issue("LOW")]
    assert _display_risk_score(scanner, issues) >= 90


def test_display_risk_score_dependency_heavy_repos_do_not_collapse_to_zero() -> None:
    scanner = ScannerService()
    issues = [
        _issue("HIGH").model_copy(
            update={
                "finding_type": "dependency_vuln",
                "category": "Dependency Vulnerability",
                "package": f"pkg{i}",
                "package_version": "1.0.0",
                "cve": f"CVE-2024-{1000 + i}",
            }
        )
        for i in range(35)
    ]
    assert _display_risk_score(scanner, issues) >= 8


def test_dependency_issue_non_production_manifest_is_downgraded() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "werkzeug",
            "version": "2.3.3",
            "cve": "CVE-2026-27199",
            "issue": "Known vulnerable dependency",
            "fix": "Upgrade to 2.3.8",
            "fix_version": "2.3.8",
            "manifest_path": "examples/celery/requirements.txt",
            "confidence": 100,
        }
    )

    assert issue.severity == "INFO"
    assert issue.confidence <= 60
    assert "non-production" in issue.message.lower()


def test_dependency_issue_production_manifest_keeps_severity() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "werkzeug",
            "version": "2.3.3",
            "cve": "CVE-2026-27199",
            "issue": "Known vulnerable dependency",
            "fix": "Upgrade to 2.3.8",
            "fix_version": "2.3.8",
            "manifest_path": "requirements.txt",
            "confidence": 100,
        }
    )

    assert issue.severity == "HIGH"


def test_dependency_issue_uses_manifest_line_and_severity_aligned_attention() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "LOW",
            "package": "flask",
            "version": "2.3.2",
            "cve": "CVE-2026-27205",
            "issue": "Known vulnerable dependency",
            "fix": "Upgrade to 3.1.3",
            "fix_version": "3.1.3",
            "manifest_path": "requirements.txt",
            "line": 42,
        }
    )

    assert issue.line == 42
    assert issue.severity == "LOW"
    assert issue.attention_level == "LOW"
    assert issue.exploitability_level == "LOW"
    assert issue.guidance.exact_fix.startswith("Upgrade") or issue.guidance.exact_fix.startswith("npm install")


def test_dependency_issue_uses_exploitability_signals_from_finding() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2020-8203",
            "issue": "Prototype Pollution",
            "fix": "Upgrade to 4.17.21",
            "fix_version": "4.17.21",
            "manifest_path": "package-lock.json",
            "ecosystem": "npm",
            "exploitability_score": 9,
            "exploitability_level": "HIGH",
            "exploitability_reasons": [
                "Public exploit available",
                "Network accessible",
                "No authentication required",
                "Low attack complexity",
            ],
            "network_access": True,
            "auth_required": False,
        }
    )

    assert issue.exploitability == "REMOTE"
    assert issue.exploitability_level == "HIGH"
    assert issue.exploitability_confidence >= 0.9
    assert issue.exploit_scenario[:2] == ["Public exploit available", "Network accessible"]


def test_dependency_issue_uses_business_impact_label() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2020-8203",
            "issue": "Prototype Pollution",
            "fix": "Upgrade to 4.17.21",
            "fix_version": "4.17.21",
            "manifest_path": "package-lock.json",
            "ecosystem": "npm",
            "impact_category": "RCE",
            "impact_label": "Remote Code Execution (RCE)",
        }
    )

    assert issue.impact_summary == "Remote Code Execution (RCE)"


def test_dependency_issue_contains_confidence_reasons() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2020-8203",
            "issue": "Prototype Pollution",
            "fix": "Upgrade to 4.17.21",
            "fix_version": "4.17.21",
            "manifest_path": "package-lock.json",
            "ecosystem": "npm",
        }
    )

    assert issue.confidence > 0
    assert len(issue.confidence_reasons) >= 2
    assert "Data source reliability" in issue.confidence_reasons[0]


def test_code_issue_contains_confidence_reasons() -> None:
    scanner = ScannerService()
    issue = scanner._finalize_issue(
        scanner="semgrep",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="server.js",
        line=12,
        message="Potential SQL injection",
        code_snippet='db.query("SELECT * FROM users WHERE id=" + req.query.id)',
    )

    assert issue.confidence > 0
    assert len(issue.confidence_reasons) >= 3
    assert any("Match accuracy" in reason for reason in issue.confidence_reasons)


def test_upgrade_message_branches_by_critical_state() -> None:
    critical_copy = _upgrade_message(is_limited=True, has_critical_issues=True)
    deep_copy = _upgrade_message(is_limited=True, has_critical_issues=False)

    assert critical_copy is not None
    assert "critical" in critical_copy.lower()
    assert deep_copy is not None
    assert "deeper analysis" in deep_copy.lower() or "low-risk" in deep_copy.lower()


def test_coverage_state_marks_insufficient_for_zero_effort_and_zero_issues() -> None:
    insufficient, message = _coverage_state(files_scanned=0, patterns_checked=0, issue_count=0)
    assert insufficient is True
    assert message is not None


def test_coverage_state_not_insufficient_when_findings_exist() -> None:
    insufficient, message = _coverage_state(files_scanned=0, patterns_checked=0, issue_count=1)
    assert insufficient is False
    assert message is None


def test_guidance_metadata_fields_are_present_in_issue_model() -> None:
    issue = _issue("LOW")
    assert issue.guidance.confidence in {"High", "Medium", "Low"}
    assert issue.guidance.guidance_type in {"template-only", "full-safe"}
    assert hasattr(issue.guidance, "fallback_reason")


def test_phase1_issue_fields_have_contract_defaults() -> None:
    issue = _issue("LOW")

    assert issue.finding_type == "code_vuln"
    assert isinstance(issue.confidence, int)
    assert issue.confidence >= 0
    assert issue.confidence_label in {"HIGH", "MEDIUM", "LOW"}
    assert isinstance(issue.exploit_scenario, list)
    assert issue.package is None
    assert issue.package_version is None
    assert issue.cve is None
    assert issue.fix_version is None


def test_repo_name_from_url_extracts_repo_segment() -> None:
    assert _repo_name_from_url("https://github.com/acme/widget") == "widget"


def test_build_file_summary_counts_occurrences() -> None:
    issues = [
        _issue("HIGH").model_copy(update={"file": "a.py", "occurrence_count": 2}),
        _issue("LOW").model_copy(update={"file": "a.py", "occurrence_count": 1}),
        _issue("MEDIUM").model_copy(update={"file": "b.py", "occurrence_count": 1}),
    ]
    summary = _build_file_summary(issues)
    assert summary["a.py"] == 3
    assert summary["b.py"] == 1


def test_score_breakdown_contains_expected_keys() -> None:
    issues = [_issue("HIGH"), _issue("MEDIUM"), _issue("LOW")]
    breakdown = _score_breakdown(issues, risk_score=62)
    assert set(breakdown.keys()) == {"code_safety", "secrets_management", "input_handling"}
    assert all(0 <= value <= 100 for value in breakdown.values())


def test_recommendations_returns_empty_list() -> None:
    recs = _recommendations([_issue("HIGH")])
    assert recs == []


def test_limit_improvement_display_caps_to_five_when_no_critical() -> None:
    issues = [_issue("LOW") for _ in range(4)] + [_issue("INFO") for _ in range(3)]

    limited = _limit_improvement_display(issues)

    assert len(limited) == 5
    assert all(item.severity in {"LOW", "INFO"} for item in limited)


def test_limit_improvement_display_keeps_all_when_critical_exists() -> None:
    issues = [_issue("HIGH")] + [_issue("LOW") for _ in range(6)]

    limited = _limit_improvement_display(issues)

    assert len(limited) == len(issues)


def test_sorting_priority_prefers_severity_then_confidence() -> None:
    high_low_conf = _issue("HIGH").model_copy(update={"confidence": 61, "confidence_label": "MEDIUM"})
    high_high_conf = _issue("HIGH").model_copy(update={"confidence": 91, "confidence_label": "HIGH"})
    medium_high_conf = _issue("MEDIUM").model_copy(update={"confidence": 98, "confidence_label": "HIGH"})

    selected = _select_ai_candidates([medium_high_conf, high_low_conf, high_high_conf], budget=3)

    assert selected[0].severity == "HIGH"
    assert selected[0].confidence == 91
    assert selected[1].severity == "HIGH"
    assert selected[2].severity == "MEDIUM"


def test_clean_repo_limit_regression_cap_is_five() -> None:
    issues = [_issue("LOW") for _ in range(10)]

    limited = _limit_improvement_display(issues)

    assert len(limited) <= 5


def test_model_rejects_malformed_security_issue_fields() -> None:
    try:
        SecurityIssue(
            title="",
            severity="MEDIUM",
            file="",
            line=0,
            scanner="",
            rule_id="",
            message="",
            confidence=120,
            confidence_label="UNKNOWN",
            exploit_scenario=["", "ok"],
            guidance=AIGuidance(explanation="x", danger="y", real_world_example="z", exact_fix=""),
        )
        assert False, "Expected model validation to fail"
    except Exception:
        assert True


def test_exploit_attachment_applies_to_high_medium_only() -> None:
    high = _issue("HIGH")
    low = _issue("LOW")

    enriched = _attach_exploit_scenarios([high, low])

    assert len(enriched[0].exploit_scenario) > 0
    assert enriched[1].exploit_scenario == []


def test_proof_output_serializes_taint_context_and_exploit_fields() -> None:
    issue = _issue("HIGH").model_copy(
        update={
            "file": "server.js",
            "line": 17,
            "rule_id": "regex.sql-injection",
            "data_source": "user_input",
            "usage_context": "database",
            "confidence": 82,
            "confidence_label": "HIGH",
            "attention_level": "HIGH",
            "framework": "express",
            "route_hint": "POST /users",
            "source_symbol": "req.body.id",
            "sink_symbol": "db.query",
            "exploitability": "reachable",
            "exploitability_level": "HIGH",
            "propagation_depth": 0,
            "propagation_chain": ["req.body.id", "id"],
        }
    )
    enriched = _attach_exploit_scenarios([issue])[0]

    report = ScanResponse(
        scan_id="scan-proof-1",
        timestamp=datetime.now(timezone.utc),
        github_url="https://github.com/acme/widget",
        repo_name="widget",
        issue_count=1,
        risk_score=62,
        issues=[enriched],
        priority_issues=[enriched],
        file_summary={"server.js": 1},
        score_breakdown={"code_safety": 62, "secrets_management": 95, "input_handling": 54},
        recommendations=["Use parameterized queries and strict input validation."],
        plan="pro",
    )

    payload = report.model_dump(mode="json")
    serialized_issue = payload["issues"][0]

    assert serialized_issue["category"] == "SQL Injection"
    assert serialized_issue["confidence"] == 82
    assert serialized_issue["attention_level"] == "HIGH"
    assert serialized_issue["exploitability_level"] == "HIGH"
    assert serialized_issue["source_symbol"] == "req.body.id"
    assert serialized_issue["sink_symbol"] == "db.query"
    assert isinstance(serialized_issue["exploit_scenario"], list)
    assert len(serialized_issue["exploit_scenario"]) >= 3


def test_aggregate_risk_semantics_allow_low_risk_with_high_attention_issue() -> None:
    issue = _issue("LOW").model_copy(
        update={
            "confidence": 100,
            "confidence_label": "HIGH",
            "exploitability_level": "HIGH",
        }
    )

    label = _aggregate_risk_label(risk_score=98, has_critical_issues=False, insufficient_coverage=False)
    explainer = _aggregate_risk_explainer()

    assert label == "Low Risk"
    assert "aggregate repository score" in explainer.lower()
    assert issue.severity == "LOW"
    assert issue.exploitability_level == "HIGH"


def test_merge_duplicate_dependency_findings_across_manifests() -> None:
    first = _issue("HIGH").model_copy(
        update={
            "finding_type": "dependency_vuln",
            "category": "Dependency Vulnerability",
            "file": "package.json",
            "rule_id": "osv.cve-2024-1111",
            "package": "multer",
            "package_version": "1.4.5-lts.1",
            "cve": "CVE-2024-1111",
        }
    )
    second = _issue("HIGH").model_copy(
        update={
            "finding_type": "dependency_vuln",
            "category": "Dependency Vulnerability",
            "file": "frontend/package.json",
            "rule_id": "osv.cve-2024-1111",
            "package": "multer",
            "package_version": "1.4.4",
            "cve": "CVE-2024-1111",
        }
    )

    merged = _merge_duplicate_issues([first, second])

    assert len(merged) == 2
    assert all(item.occurrence_count == 1 for item in merged)


def test_dependency_issue_contains_cli_and_api_output_structure() -> None:
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2020-8203",
            "issue": "Prototype Pollution",
            "fix": "Upgrade to 4.17.21",
            "fix_version": "4.17.21",
            "manifest_path": "package-lock.json",
            "ecosystem": "npm",
            "impact_category": "RCE",
            "impact_label": "Remote Code Execution (RCE)",
            "exploitability_level": "HIGH",
            "exploitability_reasons": [
                "Public exploit available",
                "No authentication required",
                "Network accessible",
            ],
        }
    )

    assert issue.fix_command == "npm install lodash@4.17.21"
    assert issue.impact_code == "RCE"
    assert issue.cli_output is not None
    assert "Package: lodash" in issue.cli_output
    assert "Installed: 4.17.15" in issue.cli_output
    assert "Safe: 4.17.21" in issue.cli_output
    assert "Exploitability: HIGH" in issue.cli_output
    assert "Impact: RCE" in issue.cli_output
    assert "Fix:" in issue.cli_output
    assert "npm install lodash@4.17.21" in issue.cli_output
    assert issue.api_output == {
        "package": "lodash",
        "severity": "HIGH",
        "exploitability": "HIGH",
        "impact": "RCE",
        "confidence": "92",
        "fix": "npm install lodash@4.17.21",
    }


def test_priority_sort_prefers_exploitability_then_severity_then_popularity() -> None:
    high_exploit_low_sev = _issue("LOW").model_copy(update={"exploitability_level": "HIGH", "occurrence_count": 1})
    med_exploit_high_sev = _issue("HIGH").model_copy(update={"exploitability_level": "MEDIUM", "occurrence_count": 10})
    high_exploit_med_sev = _issue("MEDIUM").model_copy(update={"exploitability_level": "HIGH", "occurrence_count": 3})

    ordered = sorted(
        [med_exploit_high_sev, high_exploit_low_sev, high_exploit_med_sev],
        key=lambda issue: (
            _exploitability_priority_key(issue),
            _priority_key(issue),
            _popularity_key(issue),
            _confidence_key(issue),
            _complexity_score(issue),
        ),
        reverse=True,
    )

    assert ordered[0] == high_exploit_med_sev
    assert ordered[1] == high_exploit_low_sev
    assert ordered[2] == med_exploit_high_sev
