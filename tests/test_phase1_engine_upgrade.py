from pathlib import Path

from backend.routes.scan import _attach_exploit_scenarios, _select_ai_candidates
from backend.services.dependency_scanner import DependencyScanner
from backend.services.scanner_service import ScannerService


def test_dependency_scanner_parses_npm_python_and_maven(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"^4.17.15"},"devDependencies":{"axios":"1.6.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\nrequests>=2.25\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text(
        """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>5.2.0</version>
            </dependency>
          </dependencies>
        </project>
        """,
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    deps = scanner._collect_dependencies(tmp_path)
    keys = {(dep.ecosystem, dep.name, dep.version) for dep in deps}

    assert ("npm", "lodash", "4.17.15") in keys
    assert ("npm", "axios", "1.6.0") in keys
    assert ("PyPI", "flask", "2.0.0") in keys
    assert ("PyPI", "requests", "2.25") in keys
    assert ("Maven", "org.springframework:spring-core", "5.2.0") in keys


def test_dependency_findings_are_mapped_with_fixed_confidence() -> None:
    service = ScannerService()
    finding = {
        "severity": "HIGH",
        "package": "lodash",
        "version": "4.17.15",
        "manifest_path": "package.json",
        "cve": "CVE-2020-8203",
        "issue": "Prototype pollution",
        "fix": "Upgrade to 4.17.21",
        "fix_version": "4.17.21",
        "confidence": 100,
    }

    issue = service._dependency_issue(finding)

    assert issue.finding_type == "dependency_vuln"
    assert issue.confidence == 100
    assert issue.confidence_label == "HIGH"
    assert issue.package == "lodash"
    assert issue.cve == "CVE-2020-8203"


def test_dependency_issue_includes_deterministic_poc_fields() -> None:
    service = ScannerService()
    finding = {
        "severity": "HIGH",
        "package": "lodash",
        "version": "4.17.15",
        "manifest_path": "package.json",
        "cve": "CVE-2020-8203",
        "issue": "Prototype pollution in merge utility",
        "fix": "Upgrade to 4.17.21",
        "fix_version": "4.17.21",
        "confidence": 100,
    }

    issue = service._dependency_issue(finding)

    assert issue.poc_payload == '{"__proto__": {"admin": true}}'
    assert issue.poc_command is not None and "curl -X POST" in issue.poc_command
    assert issue.poc_snippet is not None and "require(\"lodash\")" in issue.poc_snippet


def test_high_medium_findings_get_exploit_scenarios() -> None:
    service = ScannerService()
    high = service._finalize_issue(
        scanner="regex",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="api.js",
        line=10,
        message="dynamic sql",
        code_snippet="query = 'SELECT * FROM users WHERE id=' + request.args['id']",
    )
    low = service._finalize_issue(
        scanner="regex",
        rule_id="regex.improvement.debug-logging",
        scanner_title="Debug Logging",
        scanner_severity="LOW",
        file_path="auth.js",
        line=12,
        message="debug logging",
        code_snippet="console.log(request.headers.authorization)",
    )

    enriched = _attach_exploit_scenarios([high, low])

    assert len(enriched[0].exploit_scenario) > 0
    assert len(enriched[0].exploit_scenario) <= 5
    assert enriched[1].exploit_scenario == []


def test_code_issue_includes_deterministic_poc_fields() -> None:
    service = ScannerService()
    issue = service._finalize_issue(
        scanner="regex",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="api.js",
        line=10,
        message="dynamic sql",
        code_snippet="query = 'SELECT * FROM users WHERE id=' + request.args['id']",
    )

    assert issue.category == "SQL Injection"
    assert issue.poc_payload == "' OR 1=1 --"
    assert issue.poc_command is not None and "curl -X GET" in issue.poc_command
    assert issue.poc_snippet is not None and "SELECT * FROM users" in issue.poc_snippet


def test_ai_candidate_selection_prefers_higher_confidence_with_same_severity() -> None:
    service = ScannerService()
    a = service._finalize_issue(
        scanner="regex",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="a.js",
        line=1,
        message="dynamic sql",
        code_snippet="query = 'SELECT * FROM t WHERE id=' + request.args['id']",
    ).model_copy(update={"confidence": 65, "confidence_label": "MEDIUM"})

    b = service._finalize_issue(
        scanner="regex",
        rule_id="regex.sql-injection",
        scanner_title="SQL Injection",
        scanner_severity="HIGH",
        file_path="b.js",
        line=1,
        message="dynamic sql",
        code_snippet="query = 'SELECT * FROM t WHERE id=' + request.args['id']",
    ).model_copy(update={"confidence": 90, "confidence_label": "HIGH"})

    selected = _select_ai_candidates([a, b], budget=1)

    assert selected[0].confidence == 90
