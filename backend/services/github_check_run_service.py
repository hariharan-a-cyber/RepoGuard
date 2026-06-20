from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock

import httpx


class GithubCheckRunError(Exception):
    pass


@dataclass
class CheckRunLifecycleRecord:
    key: str
    check_run_id: int
    status: str
    conclusion: str | None
    updated_at: datetime


class GithubCheckRunService:
    def __init__(self) -> None:
        self._records: dict[str, CheckRunLifecycleRecord] = {}
        self._lock = Lock()

    @staticmethod
    def _github_api_base() -> str:
        return str(os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")).strip().rstrip("/")

    @staticmethod
    def _check_name() -> str:
        return str(os.getenv("GITHUB_CHECK_NAME", "RepoGuard Security Scan")).strip() or "RepoGuard Security Scan"

    @staticmethod
    def _key(repository: str, commit_sha: str) -> str:
        return f"{str(repository or '').strip().lower()}@{str(commit_sha or '').strip().lower()}"

    def _store_record(self, key: str, check_run_id: int, status: str, conclusion: str | None) -> None:
        with self._lock:
            self._records[key] = CheckRunLifecycleRecord(
                key=key,
                check_run_id=int(check_run_id),
                status=str(status),
                conclusion=(str(conclusion) if conclusion is not None else None),
                updated_at=datetime.now(timezone.utc),
            )

    def _get_record(self, key: str) -> CheckRunLifecycleRecord | None:
        with self._lock:
            return self._records.get(key)

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @staticmethod
    def _repo_parts(repository: str) -> tuple[str, str]:
        value = str(repository or "").strip()
        if "/" not in value:
            raise GithubCheckRunError("Repository must be in owner/repo format")
        owner, repo = value.split("/", 1)
        owner = owner.strip()
        repo = repo.strip()
        if not owner or not repo:
            raise GithubCheckRunError("Repository must be in owner/repo format")
        return owner, repo

    def _create_check_run(self, *, token: str, repository: str, commit_sha: str, external_id: str, summary: str) -> int:
        owner, repo = self._repo_parts(repository)
        url = f"{self._github_api_base()}/repos/{owner}/{repo}/check-runs"
        payload = {
            "name": self._check_name(),
            "head_sha": commit_sha,
            "status": "in_progress",
            "external_id": external_id,
            "output": {
                "title": "RepoGuard scan started",
                "summary": summary,
            },
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, headers=self._headers(token), json=payload)
        except httpx.HTTPError as exc:
            raise GithubCheckRunError("Failed to create check run") from exc

        if response.status_code >= 400:
            detail = response.text.strip()[:300]
            raise GithubCheckRunError(f"Create check run failed: {response.status_code} {detail}")

        data = response.json() if response.content else {}
        check_id = data.get("id")
        if not isinstance(check_id, int):
            raise GithubCheckRunError("GitHub create check run response missing id")
        return check_id

    def _find_existing_check_run(self, *, token: str, repository: str, commit_sha: str, external_id: str) -> int | None:
        owner, repo = self._repo_parts(repository)
        url = f"{self._github_api_base()}/repos/{owner}/{repo}/commits/{commit_sha}/check-runs"
        params = {"check_name": self._check_name()}

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=self._headers(token), params=params)
        except httpx.HTTPError:
            return None

        if response.status_code >= 400:
            return None

        data = response.json() if response.content else {}
        runs = data.get("check_runs") if isinstance(data, dict) else None
        if not isinstance(runs, list):
            return None

        for run in runs:
            if not isinstance(run, dict):
                continue
            run_external_id = str(run.get("external_id") or "").strip()
            run_name = str(run.get("name") or "").strip()
            run_id = run.get("id")
            if run_external_id == external_id and run_name == self._check_name() and isinstance(run_id, int):
                return run_id
        return None

    def _update_check_run(self, *, token: str, repository: str, check_run_id: int, status: str, conclusion: str | None, title: str, summary: str) -> None:
        owner, repo = self._repo_parts(repository)
        url = f"{self._github_api_base()}/repos/{owner}/{repo}/check-runs/{int(check_run_id)}"
        payload: dict[str, object] = {
            "status": status,
            "output": {
                "title": title,
                "summary": summary,
            },
        }
        if status == "completed":
            payload["completed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            payload["conclusion"] = conclusion or "neutral"

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.patch(url, headers=self._headers(token), json=payload)
        except httpx.HTTPError as exc:
            raise GithubCheckRunError("Failed to update check run") from exc

        if response.status_code >= 400:
            detail = response.text.strip()[:300]
            raise GithubCheckRunError(f"Update check run failed: {response.status_code} {detail}")

    def start_check_run(self, *, token: str, repository: str, commit_sha: str, external_id: str, summary: str) -> int:
        key = self._key(repository, commit_sha)
        discovered = self._find_existing_check_run(
            token=token,
            repository=repository,
            commit_sha=commit_sha,
            external_id=external_id,
        )
        if discovered is not None:
            self._update_check_run(
                token=token,
                repository=repository,
                check_run_id=discovered,
                status="in_progress",
                conclusion=None,
                title="RepoGuard scan restarted",
                summary=summary,
            )
            self._store_record(key, discovered, "in_progress", None)
            return discovered

        existing = self._get_record(key)
        if existing is not None:
            self._update_check_run(
                token=token,
                repository=repository,
                check_run_id=existing.check_run_id,
                status="in_progress",
                conclusion=None,
                title="RepoGuard scan restarted",
                summary=summary,
            )
            self._store_record(key, existing.check_run_id, "in_progress", None)
            return existing.check_run_id

        check_id = self._create_check_run(
            token=token,
            repository=repository,
            commit_sha=commit_sha,
            external_id=external_id,
            summary=summary,
        )
        self._store_record(key, check_id, "in_progress", None)
        return check_id

    def complete_check_run(self, *, token: str, repository: str, commit_sha: str, conclusion: str, title: str, summary: str) -> int:
        key = self._key(repository, commit_sha)
        existing = self._get_record(key)
        if existing is None:
            raise GithubCheckRunError("Cannot complete check run before start")

        self._update_check_run(
            token=token,
            repository=repository,
            check_run_id=existing.check_run_id,
            status="completed",
            conclusion=conclusion,
            title=title,
            summary=summary,
        )
        self._store_record(key, existing.check_run_id, "completed", conclusion)
        return existing.check_run_id

    def reset_for_testing(self) -> None:
        with self._lock:
            self._records.clear()


github_check_run_service = GithubCheckRunService()
