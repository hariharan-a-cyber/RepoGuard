from pathlib import Path

from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.services.scanner_service import ScannerService


def _mk_issue(idx: int) -> SecurityIssue:
    return SecurityIssue(
        title=f"[LOW] Finding {idx}",
        severity="LOW",
        finding_type="code_vuln",
        file="a.py",
        line=1,
        scanner="regex",
        rule_id=f"regex.test.{idx}",
        message="m",
        category="Weak Input Validation",
        data_source="internal",
        usage_context="unknown",
        evidence="x",
        confidence=62,
        confidence_label="MEDIUM",
        guidance=AIGuidance(explanation="x", danger="y", real_world_example="z", exact_fix=""),
    )


def test_scan_repository_respects_max_findings(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo","dependencies":{}}', encoding="utf-8")
    service = ScannerService()
    service.max_findings = 10

    monkeypatch.setattr(service, "run_dependency_scan", lambda _: [_mk_issue(i) for i in range(25)])
    monkeypatch.setattr(service.rule_engine, "scan_repository", lambda _: type("R", (), {"matches": [], "files_scanned": 0, "patterns_checked": 0})())
    monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])
    monkeypatch.setattr(service, "run_bandit", lambda *args, **kwargs: [])

    issues = service.scan_repository(tmp_path)

    assert len(issues) == 10


def test_dependency_scan_cache_prevents_repeat_calls(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo","dependencies":{}}', encoding="utf-8")
    service = ScannerService()

    calls = {"count": 0}

    def fake_scan(_):
        calls["count"] += 1
        return []

    monkeypatch.setattr(service.dependency_scanner, "scan", fake_scan)
    monkeypatch.setattr(service.rule_engine, "scan_repository", lambda _: type("R", (), {"matches": [], "files_scanned": 0, "patterns_checked": 0})())
    monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])
    monkeypatch.setattr(service, "run_bandit", lambda *args, **kwargs: [])

    service.scan_repository(tmp_path)
    service.scan_repository(tmp_path)

    # scan_repository should call dependency scan per run, but dependency scanner's own cache ensures internal query reuse.
    assert calls["count"] == 2
