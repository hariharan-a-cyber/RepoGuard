from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.ai_service import AIService  # noqa: E402
from backend.services.scanner_service import ScannerService, ScannerServiceError  # noqa: E402


def _summarize(issues) -> dict:
    severity_counts = Counter(str(issue.severity).upper() for issue in issues)
    top_findings = []
    for issue in issues[:25]:
        exact_fix = (
            getattr(issue.guidance, "exact_fix", "")
            or issue.fix_code
            or issue.fix_description
            or ""
        )
        top_findings.append(
            {
                "severity": str(issue.severity).upper(),
                "title": issue.title,
                "file": issue.file,
                "line": issue.line,
                "scanner": issue.scanner,
                "rule_id": issue.rule_id,
                "message": issue.message,
                "category": issue.category,
                "fix_description": issue.fix_description,
                "fix_code": issue.fix_code,
                "exact_fix": exact_fix,
                "guidance_type": getattr(issue.guidance, "guidance_type", "template-only"),
            }
        )

    return {
        "issues_total": len(issues),
        "severity_counts": {
            "CRITICAL": int(severity_counts.get("CRITICAL", 0)),
            "HIGH": int(severity_counts.get("HIGH", 0)),
            "MEDIUM": int(severity_counts.get("MEDIUM", 0)),
            "LOW": int(severity_counts.get("LOW", 0)),
            "INFO": int(severity_counts.get("INFO", 0)),
        },
        "top_findings": top_findings,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    repo_dir = Path(args[0]).expanduser().resolve() if args else Path.cwd().resolve()

    if not repo_dir.exists():
        print(json.dumps({"error": f"Repository path not found: {repo_dir}"}, indent=2), file=sys.stderr)
        return 2

    scanner = ScannerService()
    ai_service = AIService()

    try:
        issues = scanner.scan_repository(repo_dir)
    except ScannerServiceError as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    issues = ai_service.apply_deterministic_guidance(issues)

    summary = {"repository": str(repo_dir), **_summarize(issues)}
    print(json.dumps(summary, indent=2))

    if summary["severity_counts"]["CRITICAL"] or summary["severity_counts"]["HIGH"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())