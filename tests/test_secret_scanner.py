from pathlib import Path

from backend.services.scanner_service import ScannerService
from backend.services.secret_scanner import scan_secrets


def test_scan_secrets_detects_aws_access_key(tmp_path: Path) -> None:
    # Split literal to avoid triggering GitHub secret scanning on the test file itself.
    fake_key = "AKIA" + "1234567890ABCDEF"
    source = tmp_path / "app.py"
    source.write_text(f'AWS_KEY = "{fake_key}"\n', encoding="utf-8")

    findings = scan_secrets(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "secret"
    assert finding["name"] == "AWS Access Key"
    assert finding["severity"] == "critical"
    assert finding["file"] == "app.py"
    assert finding["line"] == 1
    assert len(finding["snippet"]) <= 120


def test_scanner_service_includes_secret_findings_in_scan(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (tmp_path / "index.js").write_text('const api_key = "abcdefghijklmnopqrstuvwxyz123456";\n', encoding="utf-8")

    service = ScannerService()
    issues = service.scan_repository(tmp_path, strict_mode=False, quick_mode=True)

    assert any(issue.finding_type == "secret" for issue in issues)
    assert any(issue.scanner == "secret_scanner" for issue in issues)
