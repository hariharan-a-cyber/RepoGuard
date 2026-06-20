import asyncio
import os
from datetime import datetime, timezone
import re
from urllib.parse import urlparse
from uuid import uuid4
from collections import OrderedDict

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import RedirectResponse

from backend.models.scan_model import (
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    StartScanResponse,
)
from backend.services.ai_service import AIService
from backend.services.auth_service import AuthError, auth_service
from backend.services.github_service import GithubService, GithubServiceError
from backend.services.history_service import history_service
from backend.services.metrics_service import metrics_service
from backend.services.scanner_service import (
    ScannerDependencyError,
    ScannerService,
    ScannerServiceError,
)

router = APIRouter()

FREE_VISIBLE_ISSUES = 2
AI_CALL_BUDGET = max(1, int(os.getenv("AI_CALL_BUDGET", "6")))
FREE_DEEP_ANALYSIS_MESSAGE = (
    "Want deeper analysis? Ship faster with complete low-risk remediation steps. Upgrade to Pro for exact copy-paste patches and full priority workflow. ₹999/month"
)
FREE_FIX_LOCK_MESSAGE = "Preview shown on Free. Upgrade to Pro to unlock exact patch code and before/after remediation snippets."
INSUFFICIENT_COVERAGE_MESSAGE = "This repository has limited analyzable source files for current security detectors."


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _priority_key(issue) -> int:
    level = issue.severity.upper()
    if level == "CRITICAL":
        return 4
    if level == "HIGH":
        return 3
    if level == "MEDIUM":
        return 2
    if level == "LOW":
        return 1
    if level == "INFO":
        return 0
    return 1


def _exploitability_priority_key(issue) -> int:
    level = str(getattr(issue, "exploitability_level", "") or "").upper()
    if level == "HIGH":
        return 3
    if level == "MEDIUM":
        return 2
    if level == "LOW":
        return 1
    return 0


def _popularity_key(issue) -> int:
    try:
        return int(getattr(issue, "occurrence_count", 1) or 1)
    except Exception:
        return 1


def _confidence_key(issue) -> int:
    try:
        return int(getattr(issue, "confidence", 0) or 0)
    except Exception:
        return 0


def _issue_identity(issue) -> str:
    return "|".join(
        [
            str(getattr(issue, "finding_type", "") or "").strip().lower(),
            str(issue.category or "").strip().lower(),
            str(issue.severity or "").strip().upper(),
            str(issue.rule_id or "").strip().lower(),
            str(issue.title or "").strip().lower(),
            str(issue.file or "").strip().lower(),
            str(issue.line or 0),
            str(getattr(issue, "package", "") or "").strip().lower(),
            str(getattr(issue, "package_version", "") or "").strip().lower(),
        ]
    )


def _is_ai_candidate(issue) -> bool:
    if str(getattr(issue, "finding_type", "") or "").lower() == "dependency_vuln":
        return False
    return str(issue.severity or "LOW").upper() in {"CRITICAL", "HIGH", "MEDIUM"}


def _severity_counts(issues: list) -> tuple[int, int, int, int]:
    critical = 0
    high = 0
    medium = 0
    low = 0
    for issue in issues:
        level = str(issue.severity or "LOW").upper()
        if level == "CRITICAL":
            critical += 1
        elif level == "HIGH":
            high += 1
        elif level == "MEDIUM":
            medium += 1
        else:
            low += 1
    return critical, high, medium, low


def _limit_improvement_display(issues: list) -> list:
    if not issues:
        return []

    has_important = any(str(issue.severity or "LOW").upper() in {"CRITICAL", "HIGH", "MEDIUM"} for issue in issues)
    if has_important:
        return issues

    # For clean repositories, keep advisory findings concise and actionable.
    return issues[:5]


def _display_risk_score(scanner: ScannerService, issues: list) -> int:
    critical, high, medium, low = _severity_counts(issues)

    if len(issues) == 0:
        return 100
    if critical == 0 and high == 0 and medium == 0:
        # Low-only findings should remain in a high trust range.
        return max(90, 100 - min(low, 5) * 2)

    base_score = scanner.calculate_risk_score(issues)

    if critical > 0:
        # Calibrated non-linear critical curve.
        # 1 -> 40, 2 -> 32, 3 -> 25, 4 -> 18, 5+ -> 10
        critical_cap = {1: 40, 2: 32, 3: 25, 4: 18}.get(critical, 10)
        return min(base_score, critical_cap)

    dependency_high_med = sum(
        1
        for issue in issues
        if str(getattr(issue, "finding_type", "") or "").lower() == "dependency_vuln"
        and str(issue.severity or "").upper() in {"HIGH", "MEDIUM"}
    )
    non_dependency_high_med = max(0, (high + medium) - dependency_high_med)

    if dependency_high_med > 0 and non_dependency_high_med == 0:
        floor = 45 if dependency_high_med >= 20 else 55
        return max(floor, base_score)

    return base_score


def _upgrade_message(is_limited: bool, has_critical_issues: bool, locked_count: int = 0) -> str | None:
    if not is_limited:
        return None
    
    if has_critical_issues:
        return (
            f"🔒 {locked_count} issues hidden\n\n"
            "Critical issues detected in this repository.\n"
            "Includes:\n"
            "- Exact vulnerable lines\n"
            "- Copy-paste fixes\n"
            "- Real exploit scenarios attackers use\n\n"
            "Fix these before your next deployment."
        )
    return FREE_DEEP_ANALYSIS_MESSAGE


def _coverage_state(files_scanned: int, patterns_checked: int, issue_count: int) -> tuple[bool, str | None]:
    insufficient = issue_count == 0 and (files_scanned <= 0 or patterns_checked <= 0)
    if insufficient:
        return True, INSUFFICIENT_COVERAGE_MESSAGE
    return False, None


def _aggregate_risk_label(risk_score: int, has_critical_issues: bool, insufficient_coverage: bool) -> str:
    if insufficient_coverage:
        return "Limited Coverage"
    if has_critical_issues:
        return "Immediate action required"
    if int(risk_score) >= 80:
        return "Low Risk"
    if int(risk_score) >= 50:
        return "Moderate risk"
    return "High risk"


def _aggregate_risk_explainer() -> str:
    return (
        "This is an aggregate repository score derived from dependency vulnerability database checks (OSV), static code analysis, and data flow tracking. "
        "Exploitability labels are best-effort and should be interpreted with code context."
    )


def _exploitability_label(confidence: float) -> str:
    if confidence > 0.75:
        return "LIKELY"
    if confidence >= 0.4:
        return "POSSIBLY"
    return "UNCLEAR"


def _impact_summary(issue) -> str:
    category = str(issue.category or "").lower()
    if "sql" in category or "injection" in category:
        return "May allow attackers to read or modify sensitive data."
    if "command" in category or "remote code" in category:
        return "May allow attackers to execute code on your server."
    if "auth" in category or "credential" in category or "secret" in category:
        return "May enable account takeover or unauthorized access."
    if "dependency vulnerability" in category:
        return "May expose exploitable paths through vulnerable package behavior."
    return "May allow attackers to compromise confidentiality, integrity, or availability."


def _estimated_fix_time_minutes(issue) -> int:
    severity = str(issue.severity or "LOW").upper()
    if severity == "CRITICAL":
        return 30
    if severity == "HIGH":
        return 20
    if severity == "MEDIUM":
        return 12
    return 8


def _complexity_score(issue) -> int:
    score = 0
    category = str(issue.category or "").lower()
    message = str(issue.message or "").lower()
    evidence = str(issue.evidence or "").lower()
    data_source = str(issue.data_source or "").lower()
    usage_context = str(issue.usage_context or "").lower()
    occurrence_count = int(getattr(issue, "occurrence_count", 1) or 1)

    high_complexity_categories = {
        "sql injection",
        "command injection",
        "unsafe yaml deserialization",
        "unsafe pickle deserialization",
    }
    if category in high_complexity_categories:
        score += 3

    if data_source == "user_input":
        score += 2

    if usage_context in {"executed", "database", "parsed"}:
        score += 2

    if any(token in (message + " " + evidence) for token in ["request", "input", "argv", "payload", "query"]):
        score += 1

    if occurrence_count > 1:
        score += min(2, occurrence_count - 1)

    return score


def _exploit_scenario(issue) -> list[str]:
    category = str(issue.category or "").lower()
    if "sql injection" in category:
        return [
            "Attacker sends crafted input through a request parameter.",
            "Input is concatenated into a SQL statement without parameter binding.",
            "Database executes attacker-controlled query logic.",
            "Attacker bypasses filters and reads or modifies sensitive records.",
        ]
    if "command injection" in category:
        return [
            "Attacker provides payload through user-controlled input.",
            "Application builds a shell command with unsanitized input.",
            "OS executes injected command tokens.",
            "Attacker gains remote command execution on the host.",
        ]
    if "hardcoded secrets" in category or "credential in url" in category:
        return [
            "Repository or logs expose embedded secret material.",
            "Attacker extracts key or credential from source artifacts.",
            "Credential is reused against target service endpoints.",
            "Attacker performs unauthorized data access or service abuse.",
        ]
    if "open redirect" in category:
        return [
            "Attacker crafts a malicious redirect target URL.",
            "Application redirects user without strict destination validation.",
            "User is sent to attacker-controlled phishing endpoint.",
            "Credentials or session tokens can be harvested.",
        ]
    if "dependency vulnerability" in category:
        return [
            "Application includes a dependency with a known public vulnerability.",
            "Attacker targets the vulnerable package behavior in runtime paths.",
            "Exploit leads to data exposure, integrity impact, or service compromise.",
            "Upgrading dependency to fixed version removes the known attack path.",
        ]
    return [
        "Attacker reaches the vulnerable code path using untrusted input.",
        "Input is processed without sufficient security controls.",
        "Application behavior can be manipulated to produce unsafe outcomes.",
        "Issue can lead to confidentiality, integrity, or availability impact.",
    ]


def _attach_exploit_scenarios(issues: list) -> list:
    updated = []
    for issue in issues:
        level = str(issue.severity or "LOW").upper()

        existing_exploitability = str(getattr(issue, "exploitability", "") or "").upper()
        if existing_exploitability in {"REMOTE", "AUTHENTICATED", "LOCAL_ONLY", "UNKNOWN", "REACHABLE", "UNREACHABLE"}:
            derived_exploitability = existing_exploitability
        else:
            derived_exploitability = "UNKNOWN"

        existing_conf = float(getattr(issue, "exploitability_confidence", 0.0) or 0.0)
        if existing_conf > 0:
            exploitability_confidence = max(0.0, min(1.0, existing_conf))
        else:
            level_hint = str(getattr(issue, "exploitability_level", "") or "").upper()
            exploitability_confidence = {
                "HIGH": 0.85,
                "MEDIUM": 0.6,
                "LOW": 0.35,
            }.get(level_hint, 0.25)

        update_dict = {
            "exploitability": derived_exploitability,
            "exploitability_confidence": exploitability_confidence,
            "exploitability_label": _exploitability_label(exploitability_confidence),
            "estimated_fix_time_minutes": _estimated_fix_time_minutes(issue),
            "impact_summary": _impact_summary(issue),
        }
        existing_scenario = list(getattr(issue, "exploit_scenario", []) or [])
        if existing_scenario:
            update_dict["exploit_scenario"] = existing_scenario[:5]
        elif level in {"CRITICAL", "HIGH", "MEDIUM"}:
            update_dict["exploit_scenario"] = _exploit_scenario(issue)[:5]
            
        updated.append(issue.model_copy(update=update_dict))
    return updated


def _select_ai_candidates(issues: list, budget: int) -> list:
    sorted_candidates = sorted(
        issues,
        key=lambda issue: (
            _priority_key(issue),
            _confidence_key(issue),
            _complexity_score(issue),
            int(getattr(issue, "occurrence_count", 1) or 1),
        ),
        reverse=True,
    )
    return [issue for issue in sorted_candidates if _is_ai_candidate(issue)][: max(0, budget)]


def _safe_repo_slug(github_url: str) -> str:
    path = urlparse(github_url).path.strip("/")
    slug = path.replace("/", "-") or "repository"
    slug = re.sub(r"[^a-zA-Z0-9._-]", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "repository"


def _repo_name_from_url(github_url: str) -> str:
    path = urlparse(github_url).path.strip("/")
    if not path:
        return "repository"
    parts = [segment for segment in path.split("/") if segment]
    return parts[-1] if parts else "repository"


def _build_file_summary(issues: list) -> dict[str, int]:
    summary: dict[str, int] = {}
    for issue in issues:
        key = str(issue.file or "unknown")
        summary[key] = summary.get(key, 0) + int(getattr(issue, "occurrence_count", 1) or 1)
    return dict(sorted(summary.items(), key=lambda pair: pair[1], reverse=True))


def _score_breakdown(issues: list, risk_score: int) -> dict[str, int]:
    code_safety = max(0, risk_score)
    secrets_management = 100
    input_handling = 100

    test_markers = ["/test", "test/", "tests/", ".test.", ".spec.", "_test.", "/__tests__/", "fixtures/"]

    seen: set[tuple[str, str, str]] = set()
    unique_issues = []
    for issue in issues:
        key = (
            str(issue.file or "").lower().replace("\\", "/"),
            str(issue.line or 0),
            str(issue.category or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_issues.append(issue)

    for issue in unique_issues:
        file_lower = str(issue.file or "").lower().replace("\\", "/")
        # Do not penalize quality scores for findings in test/fixture paths.
        if any(marker in file_lower for marker in test_markers):
            continue

        severity = str(issue.severity or "LOW").upper()
        penalty = 16 if severity == "CRITICAL" else 12 if severity == "HIGH" else 7 if severity == "MEDIUM" else 3
        category = str(issue.category or "").lower()
        if any(token in category for token in ["secret", "credential"]):
            secrets_management = max(0, secrets_management - penalty)
        if any(token in category for token in ["sql", "xss", "input", "yaml", "pickle", "command", "eval", "ssti", "template injection"]):
            input_handling = max(0, input_handling - penalty)
        if any(token in category for token in ["command", "eval", "exception", "debug", "ssti"]):
            code_safety = max(0, code_safety - penalty)

    return {
        "code_safety": code_safety,
        "secrets_management": secrets_management,
        "input_handling": input_handling,
    }


def _recommendations(issues: list) -> list[str]:
    return []


def _lock_issue_solution(issue):
    # Free tier can see all finding metadata, but fix/proof details stay locked.
    locked_guidance = issue.guidance.model_copy(
        update={
            "exact_fix": FREE_FIX_LOCK_MESSAGE,
            "real_world_example": "🔒 Upgrade to see the full exploit path.",
            "danger": issue.guidance.danger,
        }
    )
    return issue.model_copy(update={"guidance": locked_guidance})


def _free_visible_issues(issues: list, limit: int) -> list:
    if limit <= 0:
        return []
    critical = [issue for issue in issues if str(issue.severity or "").upper() == "CRITICAL"]
    high = [issue for issue in issues if str(issue.severity or "").upper() == "HIGH"]
    priority = critical + high
    if len(priority) >= limit:
        return priority[:limit]
    remainder = [
        issue
        for issue in issues
        if str(issue.severity or "").upper() not in {"CRITICAL", "HIGH"}
    ]
    return (priority + remainder)[:limit]


def _merge_duplicate_issues(issues: list):
    """Merge issues that point to the same file+line+category regardless of scanner."""
    merged: OrderedDict = OrderedDict()
    for issue in issues:
        finding_type = (getattr(issue, "finding_type", "") or "").strip().lower()

        if finding_type == "dependency_vuln":
            key = (
                "dep",
                (getattr(issue, "package", "") or "").strip().lower(),
                (getattr(issue, "cve", "") or "").strip().lower(),
                (issue.file or "").strip().lower(),
            )
        else:
            key = (
                "code",
                (issue.file or "").strip().lower(),
                str(issue.line or 0),
                (issue.category or "").strip().lower(),
            )

        existing = merged.get(key)
        if existing is None:
            merged[key] = issue.model_copy(update={"occurrence_count": 1})
        else:
            existing_conf = int(getattr(existing, "confidence", 0) or 0)
            new_conf = int(getattr(issue, "confidence", 0) or 0)
            existing_sev = _priority_key(existing)
            new_sev = _priority_key(issue)
            next_count = int(getattr(existing, "occurrence_count", 1) or 1) + 1

            if new_sev > existing_sev or (new_sev == existing_sev and new_conf > existing_conf):
                merged[key] = issue.model_copy(update={"occurrence_count": next_count})
            else:
                merged[key] = existing.model_copy(update={"occurrence_count": next_count})

    return list(merged.values())


def _apply_plan_view(scan: ScanResponse, user_plan: str = "free", has_full_access: bool = True) -> ScanResponse:
    # Payment removed: every authenticated user sees the full report.
    full_issues = list(scan.issues)
    total_issue_count = len(full_issues)
    visible_issues = full_issues

    critical_count, high_count, medium_count, low_count = _severity_counts(visible_issues)
    critical_issue_count = critical_count
    has_critical_issues = critical_issue_count > 0
    aggregate_risk_label = _aggregate_risk_label(scan.risk_score, has_critical_issues, bool(scan.insufficient_coverage))

    return scan.model_copy(
        update={
            "issues": visible_issues,
            "priority_issues": visible_issues[:3],
            "plan": "free",
            "is_limited": False,
            "visible_issue_count": len(visible_issues),
            "total_issue_count": total_issue_count,
            "locked_issue_count": 0,
            "upgrade_message": None,
            "file_summary": _build_file_summary(visible_issues),
            "score_breakdown": _score_breakdown(visible_issues, scan.risk_score),
            "recommendations": _recommendations(visible_issues),
            "critical_issue_count": critical_issue_count,
            "low_issue_count": low_count,
            "has_critical_issues": has_critical_issues,
            "aggregate_risk_label": aggregate_risk_label,
            "aggregate_risk_explainer": _aggregate_risk_explainer(),
            "access_tier": "full",
            "audit_unlocked": True,
        }
    )


async def _build_full_scan(github_url: str, strict_mode: bool = False, quick_mode: bool = False, scan_id: str | None = None) -> ScanResponse:
    temp_dir = None
    repo_dir = None
    scanner = ScannerService()
    ai_service = AIService()

    try:
        if scan_id:
            history_service.update_scan_stage(scan_id, "cloning", "Cloning repository")
        temp_dir, repo_dir = await asyncio.to_thread(GithubService.clone_repo_temp, github_url)
        if scan_id:
            mode_label = "quick" if quick_mode else "standard"
            history_service.update_scan_stage(scan_id, "analyzing", f"Running {mode_label} analyzers")
        if strict_mode:
            issues = await asyncio.to_thread(scanner.scan_repository, repo_dir, True, quick_mode)
        else:
            issues = await asyncio.to_thread(scanner.scan_repository, repo_dir, False, quick_mode)
        if scan_id:
            history_service.update_scan_stage(scan_id, "post-processing", "Merging and prioritizing findings")
        merged_issues = _merge_duplicate_issues(issues)
        merged_issues = _attach_exploit_scenarios(merged_issues)
        # Apply deterministic guidance to all issues as baseline
        merged_issues = ai_service.apply_deterministic_guidance(merged_issues)
        ai_calls_made = 0

        # Then enrich HIGH/CRITICAL issues with real AI calls
        if ai_service.enabled():
            if scan_id:
                history_service.update_scan_stage(scan_id, "ai-enrichment", "Generating AI fix guidance")
            ai_candidates = [
                i for i in merged_issues
                if str(i.severity or "").upper() in {"HIGH", "CRITICAL"}
            ][:AI_CALL_BUDGET]
            if ai_candidates:
                candidate_ids = {id(i) for i in ai_candidates}
                other_issues = [i for i in merged_issues if id(i) not in candidate_ids]
                ai_enriched = await ai_service.enrich_issues(ai_candidates)
                ai_calls_made = len(ai_enriched)
                merged_issues = ai_enriched + other_issues

        risk_score = _display_risk_score(scanner, merged_issues)
        total_issue_count = len(merged_issues)
        critical_count, high_count, medium_count, low_count = _severity_counts(merged_issues)
        critical_issue_count = critical_count
        has_critical_issues = critical_issue_count > 0
        sorted_issues = sorted(
            merged_issues,
            key=lambda issue: (
                _exploitability_priority_key(issue),
                _priority_key(issue),
                _popularity_key(issue),
                _confidence_key(issue),
                _complexity_score(issue),
            ),
            reverse=True,
        )
        display_issues = _limit_improvement_display(sorted_issues)
        display_issue_count = len(display_issues)
        insufficient_coverage, coverage_message = _coverage_state(
            scanner.last_files_scanned,
            scanner.last_patterns_checked,
            total_issue_count,
        )

        full_scan = ScanResponse(
            scan_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            github_url=github_url,
            repo_name=_repo_name_from_url(github_url),
            issue_count=display_issue_count,
            risk_score=risk_score,
            issues=display_issues,
            priority_issues=display_issues[:3],
            file_summary=_build_file_summary(display_issues),
            score_breakdown=_score_breakdown(display_issues, risk_score),
            recommendations=_recommendations(display_issues),
            plan="pro",
            is_limited=False,
            visible_issue_count=display_issue_count,
            total_issue_count=display_issue_count,
            locked_issue_count=0,
            upgrade_message=None,
            files_scanned=scanner.last_files_scanned,
            patterns_checked=scanner.last_patterns_checked,
            ai_calls_made=ai_calls_made,
            ai_calls_budget=AI_CALL_BUDGET,
            critical_issue_count=critical_issue_count,
            low_issue_count=low_count,
            has_critical_issues=has_critical_issues,
            scan_effort_valid=bool(scanner.last_files_scanned > 0 and scanner.last_patterns_checked > 0),
            insufficient_coverage=insufficient_coverage,
            coverage_message=coverage_message,
            strict_mode=bool(strict_mode),
            quick_mode=bool(quick_mode),
            analyzer_capabilities=dict(scanner.last_analyzer_capabilities),
            detected_frameworks=list(scanner.last_detected_frameworks),
        )
        return full_scan
    finally:
        if temp_dir is not None:
            await asyncio.to_thread(GithubService.cleanup_temp_dir, temp_dir)


def _is_transient_scan_error(exc: Exception) -> bool:
    text = str(exc or "").strip().lower()
    transient_tokens = {
        "timed out",
        "timeout",
        "connection",
        "temporar",
        "network",
        "rate limit",
        "429",
        "502",
        "503",
        "504",
    }
    return any(token in text for token in transient_tokens)


def _humanize_scan_failure(exc: Exception) -> str:
    """Translate an internal scan error into a clear, specific reason the user
    can act on, instead of surfacing a raw stack/exception string."""
    raw = str(exc or "").strip()
    lowered = raw.lower()

    if any(t in lowered for t in ["not found", "404", "could not read", "repository not found"]):
        return "Repository not found. Check the URL is correct and the repository is public."
    if any(t in lowered for t in ["authentication failed", "permission", "403", "private", "access denied"]):
        return "This repository appears to be private or access was denied. RepoGuard can only scan public repositories."
    if any(t in lowered for t in ["rate limit", "rate-limit", "429", "secondary rate"]):
        return "GitHub rate limit reached. Please wait a few minutes and try again."
    if any(t in lowered for t in ["timed out", "timeout"]):
        return "The repository took too long to clone or scan. Large repositories can time out - try again, or use Quick mode."
    if any(t in lowered for t in ["connection", "network", "resolve", "dns", "unreachable"]):
        return "Network error reaching GitHub. Check your connection and try again."
    if "only node.js" in lowered or "supported" in lowered or "insufficient coverage" in lowered:
        return "No scannable Node.js or Python source was found in this repository."
    if "empty" in lowered:
        return "The repository appears to be empty - there is nothing to scan."
    if "git is not installed" in lowered:
        return "Scanner misconfiguration: git is not available on the server."

    # Fall back to a trimmed version of the real error rather than a stack trace.
    cleaned = raw.splitlines()[0] if raw else "Unknown error"
    if len(cleaned) > 160:
        cleaned = cleaned[:157] + "..."
    return f"Scan failed: {cleaned}"


async def _run_scan_job(scan_id: str, user_email: str, github_url: str, strict_mode: bool = False, quick_mode: bool = False) -> None:
    history_service.mark_scan_running(scan_id, stage="initializing", message="Preparing scan")
    max_attempts = 3

    for attempt in range(1, max_attempts + 1):
        try:
            report = await _build_full_scan(github_url, strict_mode=strict_mode, quick_mode=quick_mode, scan_id=scan_id)
            report = report.model_copy(update={"scan_id": scan_id})
            history_service.complete_scan_job(user_email, scan_id, report)
            metrics_service.record(email=user_email, event="scan_completed", scan_id=scan_id)
            return
        except (GithubServiceError, ScannerDependencyError, ScannerServiceError) as exc:
            if attempt < max_attempts and _is_transient_scan_error(exc):
                retry_count = history_service.increment_retry(
                    scan_id,
                    message=f"Transient failure detected. Retrying ({attempt}/{max_attempts - 1})",
                )
                backoff_seconds = min(12, 2 ** attempt)
                history_service.update_scan_stage(
                    scan_id,
                    "retrying",
                    f"Retry {retry_count}: waiting {backoff_seconds}s before next attempt",
                )
                await asyncio.sleep(backoff_seconds)
                continue

            history_service.fail_scan_job(scan_id, _humanize_scan_failure(exc))
            metrics_service.record(email=user_email, event="scan_failed", scan_id=scan_id)
            return
        except Exception as exc:  # pragma: no cover - defensive path
            history_service.fail_scan_job(scan_id, _humanize_scan_failure(exc))
            metrics_service.record(email=user_email, event="scan_failed", scan_id=scan_id)
            return


@router.post("/scan", response_model=StartScanResponse)
async def start_scan(request: ScanRequest, authorization: str | None = Header(default=None)) -> StartScanResponse:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    github_url = request.github_url.strip()
    strict_mode = bool(request.strict_mode)
    quick_mode = bool(getattr(request, "quick_mode", False))

    try:
        github_url = GithubService.validate_public_repo_url(github_url)
    except GithubServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = history_service.start_scan_job(user.email, github_url, strict_mode=strict_mode, quick_mode=quick_mode)
    metrics_service.record(email=user.email, event="scan_started", scan_id=scan_id)
    cached = history_service.get_cached_report(user.email, github_url, strict_mode=strict_mode, quick_mode=quick_mode)
    if cached is not None:
        history_service.attach_cached_report_to_job(user.email, scan_id, cached)
        return StartScanResponse(scan_id=scan_id, status="completed")

    asyncio.create_task(_run_scan_job(scan_id, user.email, github_url, strict_mode=strict_mode, quick_mode=quick_mode))
    return StartScanResponse(scan_id=scan_id, status="pending")


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str, authorization: str | None = Header(default=None)) -> ScanStatusResponse:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    job = history_service.get_scan_job(user.email, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.status == "failed":
        return ScanStatusResponse(
            scan_id=scan_id,
            status="failed",
            message=job.error or "Scan failed",
            stage=job.stage,
            retry_count=job.retry_count,
        )
    if job.status != "completed" or job.result is None:
        return ScanStatusResponse(
            scan_id=scan_id,
            status=job.status,
            message=job.status_message or "Scan in progress",
            stage=job.stage,
            retry_count=job.retry_count,
        )

    report = _apply_plan_view(job.result)
    return ScanStatusResponse(
        scan_id=scan_id,
        status="completed",
        message="Scan completed",
        stage="completed",
        retry_count=job.retry_count,
        report=report,
    )


@router.get("/history", response_model=list[ScanHistoryItem])
def get_history(authorization: str | None = Header(default=None)) -> list[ScanHistoryItem]:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.get_user_by_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return history_service.list_scans(user.email)


@router.get("/report/{scan_id}/share")
def share_report(scan_id: str) -> dict:
    # Public share route returns a sanitized free-plan version only.
    job = history_service.get_any_scan_job(scan_id)
    if job is None or job.result is None:
        raise HTTPException(status_code=404, detail="Report not found")
    public_report = _apply_plan_view(job.result)
    return {"scan_id": scan_id, "report": public_report}


_GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


@router.get("/badge/{repo_owner}/{repo_name}")
def security_badge(repo_owner: str, repo_name: str) -> RedirectResponse:
    if not _GITHUB_NAME_RE.match(repo_owner or "") or not _GITHUB_NAME_RE.match(repo_name or ""):
        raise HTTPException(status_code=400, detail="Invalid repository owner or name")
    github_url = f"https://github.com/{repo_owner}/{repo_name}"
    latest_scan = history_service.get_latest_scan_for_repo(github_url)
    score = int(getattr(latest_scan, "risk_score", 85) or 85)
    score = max(0, min(100, score))
    color = "brightgreen" if score >= 80 else "yellow" if score >= 50 else "red"
    label = f"security%3A{score}%2F100"
    svg_url = f"https://img.shields.io/badge/{label}-{color}"
    return RedirectResponse(url=svg_url, status_code=302)



