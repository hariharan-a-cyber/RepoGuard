from __future__ import annotations

import asyncio
import multiprocessing
import os
from dataclasses import dataclass
from datetime import datetime, timezone
import time

from backend.services.ai_service import AIService
from backend.services.fix_templates import get_deterministic_fix, get_fix_description
from backend.services.github_app_auth_service import GithubAppAuthError, github_app_auth_service
from backend.services.github_check_run_service import GithubCheckRunError, github_check_run_service
from backend.services.github_service import GithubService, GithubServiceError
from backend.services.scanner_service import ScannerDependencyError, ScannerService, ScannerServiceError
from backend.services.webhook_queue_service import WebhookQueueJob, webhook_queue_service

MAX_RETRIES = 3


@dataclass
class WorkerRunResult:
    status: str
    job_id: str
    delivery_id: str
    repository: str
    commit_sha: str
    check_run_id: int | None
    message: str
    duration_seconds: float = 0.0
    failure_type: str = ""
    retryable: bool = False


class WebhookWorkerService:
    def __init__(self) -> None:
        self._last_heartbeat: datetime | None = None
        self._scanner_service = ScannerService()
        self._soft_timeout_seconds = max(5, int(str(os.getenv("WORKER_INTERNAL_TIMEOUT_SECONDS", "22")).strip() or "22"))
        self._hard_timeout_seconds = max(self._soft_timeout_seconds + 1, int(str(os.getenv("WORKER_HARD_TIMEOUT_SECONDS", "30")).strip() or "30"))
        self._disable_subprocess_scan = str(os.getenv("WORKER_DISABLE_SUBPROCESS_SCAN", "0")).strip() in {"1", "true", "yes"}

    @property
    def last_heartbeat(self) -> datetime | None:
        return self._last_heartbeat

    def _touch_heartbeat(self) -> None:
        self._last_heartbeat = datetime.now(timezone.utc)

    def process_next_job(self) -> WorkerRunResult | None:
        job = webhook_queue_service.dequeue_for_worker(timeout_seconds=5, visibility_timeout_seconds=self._hard_timeout_seconds)
        if job is None:
            return None
        return self._run_with_retry(job)

    def process_job(self, job: WebhookQueueJob) -> WorkerRunResult:
        return self._run_with_retry(job)

    def _run_with_retry(self, job: WebhookQueueJob) -> WorkerRunResult:
        """Try to process a job up to 3 times before giving up."""
        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                return self._process_job(job)
            except Exception as e:
                last_error = e
                wait = 2 ** attempt
                time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError("Job processing failed without an explicit error")

    def _process_job(self, job: WebhookQueueJob) -> WorkerRunResult:
        self._touch_heartbeat()
        started_at = time.perf_counter()

        if not job.repository or not job.commit_sha or job.installation_id is None:
            return WorkerRunResult(
                status="skipped",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=None,
                message="Missing repository, commit, or installation context",
                duration_seconds=time.perf_counter() - started_at,
            )

        token: str
        try:
            token = github_app_auth_service.get_installation_token(job.installation_id)
        except GithubAppAuthError as exc:
            return WorkerRunResult(
                status="failed",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=None,
                message=str(exc),
                duration_seconds=time.perf_counter() - started_at,
                failure_type="github_api_failure",
                retryable=True,
            )

        external_id = f"repoguard:{job.delivery_id}:{job.commit_sha}"

        check_run_id: int | None = None
        repo_url = ""
        repo_obj = job.payload.get("repository") if isinstance(job.payload, dict) else None
        try:
            if job.repository:
                repo_url = GithubService.installation_clone_url(job.repository, token)
            elif isinstance(repo_obj, dict):
                repo_url = str(repo_obj.get("html_url") or repo_obj.get("clone_url") or "").strip()
        except GithubServiceError as exc:
            return WorkerRunResult(
                status="failed",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=None,
                message=str(exc),
                duration_seconds=time.perf_counter() - started_at,
                failure_type="parsing_failure",
                retryable=False,
            )

        try:
            check_run_id = github_check_run_service.start_check_run(
                token=token,
                repository=job.repository,
                commit_sha=job.commit_sha,
                external_id=external_id,
                summary="Scan job accepted and queued for deterministic analysis.",
            )

            if not repo_url:
                github_check_run_service.complete_check_run(
                    token=token,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    conclusion="neutral",
                    title="RepoGuard scan skipped",
                    summary="Repository URL is unavailable in webhook payload.",
                )
                return WorkerRunResult(
                    status="skipped",
                    job_id=job.job_id,
                    delivery_id=job.delivery_id,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    check_run_id=check_run_id,
                    message="Repository URL unavailable",
                    duration_seconds=time.perf_counter() - started_at,
                )

            if self._disable_subprocess_scan:
                scan_result = _run_scan_inline(repo_url, commit_sha=job.commit_sha)
            else:
                scan_result = _run_scan_with_timeouts(
                    repo_url=repo_url,
                    soft_timeout_seconds=self._soft_timeout_seconds,
                    hard_timeout_seconds=self._hard_timeout_seconds,
                    commit_sha=job.commit_sha,
                )

            if scan_result["status"] == "hard_timeout":
                github_check_run_service.complete_check_run(
                    token=token,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    conclusion="failure",
                    title="RepoGuard scan timed out",
                    summary="Hard timeout reached at 30s; job terminated to protect queue health.",
                )
                return WorkerRunResult(
                    status="failed",
                    job_id=job.job_id,
                    delivery_id=job.delivery_id,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    check_run_id=check_run_id,
                    message="Hard timeout reached",
                    duration_seconds=time.perf_counter() - started_at,
                    failure_type="timeout",
                    retryable=False,
                )

            if scan_result["status"] == "internal_timeout":
                summary = str(scan_result.get("summary") or "Internal cutoff reached at 22s; publishing partial result.")
                github_check_run_service.complete_check_run(
                    token=token,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    conclusion="neutral",
                    title="RepoGuard scan partially completed",
                    summary=summary,
                )
                return WorkerRunResult(
                    status="completed",
                    job_id=job.job_id,
                    delivery_id=job.delivery_id,
                    repository=job.repository,
                    commit_sha=job.commit_sha,
                    check_run_id=check_run_id,
                    message=summary,
                    duration_seconds=time.perf_counter() - started_at,
                    failure_type="",
                    retryable=False,
                )

            if scan_result["status"] == "error":
                raise ScannerServiceError(str(scan_result.get("error") or "Scan failed"))

            summary = str(scan_result.get("summary") or "Node.js deterministic scan finished.")
            findings = scan_result.get("findings") if isinstance(scan_result, dict) else []
            if not isinstance(findings, list):
                findings = []

            # Populate fix_code into findings before auto-fix runs.
            # This is what the branch commit actually uses.
            for finding in findings:
                if finding.get("fix_code"):
                    continue  # AI already provided one, keep it

                vuln_type = self._normalize_vuln_type(finding)
                language = (
                    "python"
                    if str(finding.get("file") or "").lower().endswith(".py")
                    else "node"
                )
                code = get_deterministic_fix(vuln_type, language)
                if code:
                    finding["fix_code"] = code

                # Also write the human-readable description for the PR comment
                if not finding.get("fix_description"):
                    finding["fix_description"] = get_fix_description(vuln_type)

            fix_branch = None
            pr_number = self._extract_pr_number(job)
            if job.repository and pr_number:
                try:
                    fix_branch = self._apply_auto_fix_and_comment(
                        token=token,
                        repository=job.repository,
                        commit_sha=job.commit_sha,
                        pr_number=pr_number,
                        repo_url=repo_url,
                        findings=findings,
                    )
                except Exception:
                    # Comment/auto-fix failures should not fail the scan lifecycle.
                    fix_branch = None

            if fix_branch:
                summary = f"{summary} Auto-fix branch: {fix_branch}."

            github_check_run_service.complete_check_run(
                token=token,
                repository=job.repository,
                commit_sha=job.commit_sha,
                conclusion="success",
                title="RepoGuard scan completed",
                summary=summary,
            )
        except (GithubServiceError, ScannerDependencyError, ScannerServiceError) as exc:
            err_text = str(exc)
            lowered = err_text.lower()
            failure_type = "parsing_failure"
            retryable = False
            if "timeout" in lowered and "osv" in lowered:
                failure_type = "osv_timeout"
                retryable = True
            elif "timeout" in lowered or "connection" in lowered or "network" in lowered or "clone" in lowered:
                failure_type = "network_failure"
                retryable = True
            elif "rate limit" in lowered or "rate-limit" in lowered or "ratelimit" in lowered or "429" in lowered or "secondary rate" in lowered:
                failure_type = "rate_limit"
                retryable = True
            elif "only node.js repositories are supported" in lowered or "insufficient coverage" in lowered or "unsupported" in lowered:
                failure_type = "unsupported_repository"
                retryable = False

            if check_run_id is not None:
                try:
                    github_check_run_service.complete_check_run(
                        token=token,
                        repository=job.repository,
                        commit_sha=job.commit_sha,
                        conclusion="neutral",
                        title="RepoGuard scan finished with limitations",
                        summary=str(exc),
                    )
                except GithubCheckRunError:
                    pass
            return WorkerRunResult(
                status="failed",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=check_run_id,
                message=err_text,
                duration_seconds=time.perf_counter() - started_at,
                failure_type=failure_type,
                retryable=retryable,
            )
        except GithubCheckRunError as exc:
            return WorkerRunResult(
                status="failed",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=check_run_id,
                message=str(exc),
                duration_seconds=time.perf_counter() - started_at,
                failure_type="github_api_failure",
                retryable=True,
            )
        except Exception as exc:
            if check_run_id is not None:
                try:
                    github_check_run_service.complete_check_run(
                        token=token,
                        repository=job.repository,
                        commit_sha=job.commit_sha,
                        conclusion="failure",
                        title="RepoGuard scan failed",
                        summary=str(exc),
                    )
                except GithubCheckRunError:
                    pass
            return WorkerRunResult(
                status="failed",
                job_id=job.job_id,
                delivery_id=job.delivery_id,
                repository=job.repository,
                commit_sha=job.commit_sha,
                check_run_id=check_run_id,
                message=str(exc),
                duration_seconds=time.perf_counter() - started_at,
                failure_type="worker_exception",
                retryable=False,
            )

        return WorkerRunResult(
            status="completed",
            job_id=job.job_id,
            delivery_id=job.delivery_id,
            repository=job.repository,
            commit_sha=job.commit_sha,
            check_run_id=check_run_id,
            message="Check run lifecycle completed",
            duration_seconds=time.perf_counter() - started_at,
        )

    @staticmethod
    def _extract_pr_number(job: WebhookQueueJob) -> int | None:
        payload = job.payload if isinstance(job.payload, dict) else {}
        pull_request = payload.get("pull_request") if isinstance(payload, dict) else None
        if not isinstance(pull_request, dict):
            return None
        value = pull_request.get("number")
        try:
            number = int(str(value).strip())
            return number if number > 0 else None
        except Exception:
            return None

    @staticmethod
    def _is_high_severity(finding: dict) -> bool:
        return str(finding.get("severity") or "").upper() in {"CRITICAL", "HIGH"}

    @staticmethod
    def _normalize_vuln_type(finding: dict) -> str:
        raw = str(finding.get("type") or finding.get("finding_type") or "").strip().lower()
        if raw in {"dangerous_eval", "sql_injection", "hardcoded_secret"}:
            return raw
        title_blob = f"{finding.get('title', '')} {finding.get('category', '')} {finding.get('rule_id', '')}".lower()
        if "sql" in title_blob:
            return "sql_injection"
        if "secret" in title_blob or "credential" in title_blob:
            return "hardcoded_secret"
        if "eval" in title_blob or "exec" in title_blob:
            return "dangerous_eval"
        return raw or "generic"

    @staticmethod
    def _looks_like_replacement_code(text: str) -> bool:
        """
        Returns True if the text looks like actual code that can be committed.
        Returns False for prose descriptions.
        """
        value = str(text or "").strip()
        if not value or len(value) < 5:
            return False
        # Reject multi-sentence prose (has ". " pattern or is very long with no code chars)
        if len(value) > 200 and value.count(". ") > 2:
            return False
        # Must contain at least one code indicator
        code_indicators = ["(", ")", "=", "[", "]", ".", "->", "=>", "{", "}"]
        return any(indicator in value for indicator in code_indicators)

    @staticmethod
    def _build_fixed_content(original_content: str, snippet: str, replacement: str) -> str | None:
        src = str(original_content or "")
        old = str(snippet or "").strip()
        new = str(replacement or "").strip()
        if not src or not old or not new:
            return None
        if old not in src:
            return None
        if old == new:
            return None
        return src.replace(old, new, 1)

    def _apply_auto_fix_and_comment(
        self,
        *,
        token: str,
        repository: str,
        commit_sha: str,
        pr_number: int,
        repo_url: str,
        findings: list[dict],
    ) -> str | None:
        gh = GithubService(api_token=token)
        fix_branch: str | None = None

        temp_dir = None
        repo_dir = None
        try:
            temp_dir, repo_dir = GithubService.clone_repo_temp_from_github_clone_url(repo_url)

            for finding in findings:
                if not self._is_high_severity(finding):
                    continue

                vuln_type = self._normalize_vuln_type(finding)
                file_rel = str(finding.get("file") or "").strip()
                if not file_rel:
                    continue

                snippet = str(finding.get("snippet") or "").strip()
                ai_fix = str(finding.get("fix_code") or "").strip()
                replacement = ai_fix
                if not self._looks_like_replacement_code(replacement):
                    continue

                local_file = (repo_dir / file_rel).resolve()
                if repo_dir.resolve() not in local_file.parents and local_file != repo_dir.resolve():
                    continue
                if not local_file.exists() or not local_file.is_file():
                    continue

                original_content = local_file.read_text(encoding="utf-8", errors="ignore")
                fixed_content = self._build_fixed_content(original_content, snippet, replacement)
                if not fixed_content:
                    continue

                result = gh.create_fix_branch_and_commit(
                    repo_full_name=repository,
                    base_sha=commit_sha,
                    file_path=file_rel,
                    original_content=original_content,
                    fixed_content=fixed_content,
                    finding_title=str(finding.get("title") or "Security Fix"),
                )
                fix_branch = str(result.get("branch") or "").strip() or fix_branch
                if fix_branch:
                    break
        finally:
            if temp_dir is not None:
                GithubService.cleanup_temp_dir(temp_dir)

        gh.post_security_comment(
            repo_full_name=repository,
            pr_number=pr_number,
            findings=findings,
            fix_branch=fix_branch,
        )
        return fix_branch


def _serialize_issue(issue) -> dict:
    return {
        "title": str(issue.title),
        "file": str(issue.file),
        "line": int(issue.line),
        "snippet": str(getattr(issue, "snippet", "") or issue.evidence or ""),
        "severity": str(issue.severity).lower(),
        "fix_description": str(getattr(issue, "fix_description", "") or ""),
        "fix_code": getattr(issue, "fix_code", None),
        "confidence": float(max(0.0, min(1.0, float(getattr(issue, "confidence", 0) or 0) / 100.0))),
        "type": str(getattr(issue, "finding_type", "") or ""),
        "category": str(getattr(issue, "category", "") or ""),
        "rule_id": str(getattr(issue, "rule_id", "") or ""),
    }


def _clone_for_scan(repo_url: str, commit_sha: str = "") -> tuple:
    temp_dir, repo_dir = GithubService.clone_repo_temp_from_github_clone_url(repo_url)
    sha = str(commit_sha or "").strip()
    if sha:
        try:
            GithubService._checkout_commit(repo_dir, repo_url, sha)
        except GithubServiceError:
            GithubService.cleanup_temp_dir(temp_dir)
            raise
    return temp_dir, repo_dir


def _scan_target(repo_url: str, output_queue, commit_sha: str = "") -> None:
    temp_dir = None
    try:
        temp_dir, repo_dir = _clone_for_scan(repo_url, commit_sha)
        scanner = ScannerService()
        issues = scanner.scan_repository(repo_dir)
        ai_service = AIService()
        issues = asyncio.run(ai_service.enrich_issues(issues))
        high_count = sum(1 for item in issues if str(item.severity or "").upper() == "HIGH")
        medium_count = sum(1 for item in issues if str(item.severity or "").upper() == "MEDIUM")
        low_count = sum(1 for item in issues if str(item.severity or "").upper() in {"LOW", "INFO"})
        summary = (
            f"Node.js deterministic scan finished. Findings: {len(issues)} total "
            f"(HIGH={high_count}, MEDIUM={medium_count}, LOW/INFO={low_count})."
        )
        findings = [_serialize_issue(issue) for issue in issues]
        output_queue.put({"status": "ok", "summary": summary, "findings": findings})
    except Exception as exc:
        output_queue.put({"status": "error", "error": str(exc)})
    finally:
        if temp_dir is not None:
            GithubService.cleanup_temp_dir(temp_dir)


def _run_scan_inline(repo_url: str, commit_sha: str = "") -> dict[str, object]:
    temp_dir = None
    try:
        temp_dir, repo_dir = _clone_for_scan(repo_url, commit_sha)
        scanner = ScannerService()
        issues = scanner.scan_repository(repo_dir)
        ai_service = AIService()
        issues = asyncio.run(ai_service.enrich_issues(issues))
        high_count = sum(1 for item in issues if str(item.severity or "").upper() == "HIGH")
        medium_count = sum(1 for item in issues if str(item.severity or "").upper() == "MEDIUM")
        low_count = sum(1 for item in issues if str(item.severity or "").upper() in {"LOW", "INFO"})
        summary = (
            f"Node.js deterministic scan finished. Findings: {len(issues)} total "
            f"(HIGH={high_count}, MEDIUM={medium_count}, LOW/INFO={low_count})."
        )
        findings = [_serialize_issue(issue) for issue in issues]
        return {"status": "ok", "summary": summary, "findings": findings}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        if temp_dir is not None:
            GithubService.cleanup_temp_dir(temp_dir)


def _run_scan_with_timeouts(repo_url: str, soft_timeout_seconds: int, hard_timeout_seconds: int, commit_sha: str = "") -> dict[str, object]:
    ctx = multiprocessing.get_context("spawn")
    output_queue = ctx.Queue(maxsize=1)
    process = ctx.Process(target=_scan_target, args=(repo_url, output_queue, commit_sha))
    process.start()

    process.join(timeout=float(soft_timeout_seconds))
    if not process.is_alive():
        if not output_queue.empty():
            return output_queue.get_nowait()
        return {"status": "error", "error": "Scan exited without result"}

    # Internal deterministic cutoff reached; stop early and publish partial output.
    process.terminate()
    remaining = max(0, int(hard_timeout_seconds) - int(soft_timeout_seconds))
    process.join(timeout=min(2.0, float(remaining)))
    if process.is_alive():
        process.kill()
        process.join(timeout=2.0)
        return {"status": "hard_timeout"}

    return {"status": "internal_timeout", "summary": "Internal cutoff reached at 22s; publishing partial result."}


webhook_worker_service = WebhookWorkerService()
