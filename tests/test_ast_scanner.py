from pathlib import Path

from backend.services.ast_scanner import TREE_SITTER_AVAILABLE, hybrid_analyze_file
from backend.services.scanner_service import ScannerService


def test_hybrid_analyze_file_skips_when_no_eval_or_exec(tmp_path: Path) -> None:
    file_path = tmp_path / "safe.js"
    content = "const value = 42;\n"
    findings = hybrid_analyze_file(file_path, content)
    assert findings == []


def test_hybrid_analyze_file_javascript_detects_eval_call() -> None:
    if not TREE_SITTER_AVAILABLE:
        return

    file_path = Path("unsafe.js")
    code = "eval(userInput);\n"
    findings = hybrid_analyze_file(file_path, code)

    assert len(findings) >= 1
    assert findings[0]["type"] == "dangerous_eval"
    assert findings[0]["severity"] == "high"


def test_scanner_service_run_ast_scan_includes_detected_issue(tmp_path: Path) -> None:
    if not TREE_SITTER_AVAILABLE:
        return

    source = tmp_path / "unsafe.js"
    source.write_text("eval(req.query.x);\n", encoding="utf-8")

    service = ScannerService()
    issues = service.run_ast_scan(tmp_path)

    assert any(issue.scanner == "ast_scanner" for issue in issues)
    assert any("eval" in issue.title.lower() or "dynamic" in issue.title.lower() for issue in issues)
    assert any((issue.fix_code or "").strip() for issue in issues)
