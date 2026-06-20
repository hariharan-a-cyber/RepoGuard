from pathlib import Path

from backend.services.rule_engine import RuleMatch, RuleResult
from backend.services.scanner_service import ScannerService


def _run_with_single_rule(tmp_path: Path, snippet: str) -> list:
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
                    snippet=snippet,
                )
            ],
            files_scanned=1,
            patterns_checked=5,
        )

    service.max_findings = 50
    service.bandit_timeout_seconds = 1
    service.semgrep_timeout_seconds = 1
    service._has_python_files = lambda _: False
    service.run_dependency_scan = lambda _: []
    service.rule_engine.scan_repository = fake_rule_scan
    service.run_semgrep = lambda *args, **kwargs: []

    return service.scan_repository(tmp_path)


def test_source_only_is_not_emitted(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.body.id;
          res.send(id);
        });
        """,
        encoding="utf-8",
    )

    issues = _run_with_single_rule(tmp_path, 'const id = req.body.id;')
    assert issues == []


def test_sink_only_is_suppressed(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        """
        app.get('/users', (req, res) => {
          db.query("SELECT * FROM users WHERE id=1");
        });
        """,
        encoding="utf-8",
    )

    issues = _run_with_single_rule(tmp_path, 'db.query("SELECT * FROM users WHERE id=1");')
    assert issues == []


def test_encoded_flow_is_not_treated_as_sanitized(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.body.id;
          const safe = encodeURIComponent(id);
          db.query("SELECT * FROM users WHERE id=" + safe);
        });
        """,
        encoding="utf-8",
    )

    issues = _run_with_single_rule(
        tmp_path,
        'const id = req.body.id; const safe = encodeURIComponent(id); db.query("SELECT * FROM users WHERE id=" + safe);',
    )
    assert len(issues) == 1
    assert issues[0].category == "SQL Injection"


def test_broken_or_transformed_flow_is_medium_not_high(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.body.id;
          const shaped = hash(id);
          db.query("SELECT * FROM users WHERE id=" + shaped);
        });
        """,
        encoding="utf-8",
    )

    issues = _run_with_single_rule(
        tmp_path,
        'const id = req.body.id; const shaped = hash(id); db.query("SELECT * FROM users WHERE id=" + shaped);',
    )

    assert len(issues) == 1
    issue = issues[0]
    assert issue.exploitability_level == "MEDIUM"
    assert issue.confidence <= 84
