from pathlib import Path

import pytest

from backend.services.scanner_service import ScannerService, ScannerServiceError
from backend.services.rule_engine import RuleMatch, RuleResult


def test_sql_injection_regex_issue_confirmed_with_taint(tmp_path: Path) -> None:
    file_path = tmp_path / "server.js"
    file_path.write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.query.id;
          db.query("SELECT * FROM users WHERE id=" + id);
        });
        """,
        encoding="utf-8",
    )

    service = ScannerService()
    issue = service._finalize_issue(
        scanner="regex",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="server.js",
        line=3,
        message="Potential SQL Injection",
        code_snippet='db.query("SELECT * FROM users WHERE id=" + id);',
    )
    flows = service.taint_service.scan_repository(tmp_path)

    finalized = service._apply_taint_context([issue], flows)

    assert len(finalized) == 1
    issue = finalized[0]
    assert issue.framework == "express"
    assert issue.source_symbol
    assert issue.sink_symbol
    assert issue.exploitability == "reachable"
    assert issue.exploitability_level == "HIGH"
    assert issue.propagation_depth == 0


def test_open_redirect_regex_issue_retained_for_encoded_flow(tmp_path: Path) -> None:
    file_path = tmp_path / "server.js"
    file_path.write_text(
        """
        app.get('/login', (req, res) => {
          const next = req.query.next;
          res.redirect(encodeURIComponent(next));
        });
        """,
        encoding="utf-8",
    )

    service = ScannerService()
    issue = service._finalize_issue(
        scanner="regex",
        rule_id="regex.open-redirect",
        scanner_title="Open Redirect",
        scanner_severity="MEDIUM",
        file_path="server.js",
        line=3,
        message="Potential open redirect",
        code_snippet="res.redirect(encodeURIComponent(next));",
    )
    flows = service.taint_service.scan_repository(tmp_path)

    finalized = service._apply_taint_context([issue], flows)

    assert len(finalized) == 1
    assert finalized[0].category == "Open Redirect"
    assert finalized[0].exploitability == "reachable"


def test_scan_repository_enriches_regex_sql_issue_with_taint(monkeypatch, tmp_path: Path) -> None:
    file_path = tmp_path / "server.js"
    file_path.write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.query.id;
          db.query("SELECT * FROM users WHERE id=" + id);
        });
        """,
        encoding="utf-8",
    )

    service = ScannerService()

    def fake_rule_scan(_):
        return RuleResult(
            matches=[
                RuleMatch(
                    name="SQL Injection String Concatenation",
                    rule_id="regex.sql-injection",
                    severity="HIGH",
                    message="Potential SQL injection via dynamic query construction.",
                    file_path="server.js",
                    line=2,
                    snippet='const id = req.query.id; db.query("SELECT * FROM users WHERE id=" + id);',
                )
            ],
            files_scanned=1,
            patterns_checked=5,
        )

    monkeypatch.setattr(service, "run_dependency_scan", lambda _: [])
    monkeypatch.setattr(service.rule_engine, "scan_repository", fake_rule_scan)
    monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])

    issues = service.scan_repository(tmp_path)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.category == "SQL Injection"
    assert issue.framework == "express"
    assert issue.source_symbol
    assert issue.sink_symbol
    assert issue.exploitability == "reachable"
    assert issue.exploitability_level == "HIGH"
    assert 80 <= issue.confidence <= 92


def test_scan_repository_records_analyzer_capabilities(monkeypatch, tmp_path: Path) -> None:
        file_path = tmp_path / "server.js"
        file_path.write_text(
                """
                app.get('/users', (req, res) => {
                    const id = req.query.id;
                    db.query("SELECT * FROM users WHERE id=" + id);
                });
                """,
                encoding="utf-8",
        )

        service = ScannerService()
        monkeypatch.setattr(service, "run_dependency_scan", lambda _: [])
        monkeypatch.setattr(service.rule_engine, "scan_repository", lambda _: RuleResult(matches=[], files_scanned=1, patterns_checked=5))
        monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])

        issues = service.scan_repository(tmp_path)

        assert isinstance(issues, list)
        assert service.last_analyzer_capabilities["dependency_scanner"] is True
        assert service.last_analyzer_capabilities["rule_engine"] is True
        assert service.last_analyzer_capabilities["taint_service"] is True
        assert service.last_analyzer_capabilities["semgrep"] is True
        assert "express" in service.last_detected_frameworks


def test_scan_repository_rejects_go_repository(monkeypatch, tmp_path: Path) -> None:
    file_path = tmp_path / "server.go"
    file_path.write_text(
        """
        package main

        import "net/http"

        func handler(w http.ResponseWriter, r *http.Request) {
            id := r.URL.Query().Get("id")
            query := "SELECT * FROM users WHERE id=" + id
            db.Query(query)
        }
        """,
        encoding="utf-8",
    )

    service = ScannerService()

    def fake_rule_scan(_):
        return RuleResult(
            matches=[
                RuleMatch(
                    name="SQL Injection String Concatenation",
                    rule_id="regex.sql-injection",
                    severity="HIGH",
                    message="Potential SQL injection via dynamic query construction.",
                    file_path="server.go",
                    line=8,
                    snippet='id := r.URL.Query().Get("id"); query := "SELECT * FROM users WHERE id=" + id; db.Query(query)',
                )
            ],
            files_scanned=1,
            patterns_checked=5,
        )

    monkeypatch.setattr(service, "run_dependency_scan", lambda _: [])
    monkeypatch.setattr(service.rule_engine, "scan_repository", fake_rule_scan)
    monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])

    with pytest.raises(ScannerServiceError, match="Only Node.js repositories are supported"):
        service.scan_repository(tmp_path)


def test_scan_repository_rejects_csharp_repository(monkeypatch, tmp_path: Path) -> None:
    file_path = tmp_path / "Runner.cs"
    file_path.write_text(
        """
        using System.Diagnostics;
        using Microsoft.AspNetCore.Mvc;

        public class RunnerController : ControllerBase
        {
            public void Run()
            {
                var cmd = Request.Query["cmd"];
                Process.Start(cmd);
            }
        }
        """,
        encoding="utf-8",
    )

    service = ScannerService()

    def fake_rule_scan(_):
        return RuleResult(
            matches=[
                RuleMatch(
                    name="Command Injection",
                    rule_id="regex.command-injection",
                    severity="HIGH",
                    message="Potential command execution with untrusted input.",
                    file_path="Runner.cs",
                    line=10,
                    snippet='var cmd = Request.Query["cmd"]; Process.Start(cmd);',
                )
            ],
            files_scanned=1,
            patterns_checked=5,
        )

    monkeypatch.setattr(service, "run_dependency_scan", lambda _: [])
    monkeypatch.setattr(service.rule_engine, "scan_repository", fake_rule_scan)
    monkeypatch.setattr(service, "run_semgrep", lambda *args, **kwargs: [])

    with pytest.raises(ScannerServiceError, match="Only Node.js repositories are supported"):
        service.scan_repository(tmp_path)
