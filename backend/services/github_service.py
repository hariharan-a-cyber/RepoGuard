import re
import shutil
import subprocess
import tempfile
import os
import httpx
from pathlib import Path
from urllib.parse import quote, urlparse


class GithubServiceError(Exception):
    pass


class GithubService:
    GITHUB_PATTERN = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")

    def __init__(self, api_token: str | None = None) -> None:
        self._api_token = str(api_token or "").strip()
        self._api_base = str(os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")).strip().rstrip("/")

    def _headers(self) -> dict[str, str]:
        if not self._api_token:
            raise GithubServiceError("Missing GitHub API token")
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _github_api_get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._api_base}{path}"
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.get(url, headers=self._headers(), params=params)
        except httpx.HTTPError as exc:
            raise GithubServiceError("GitHub API GET request failed") from exc
        if response.status_code >= 400:
            detail = (response.text or "").strip()[:300]
            raise GithubServiceError(f"GitHub API GET failed: {response.status_code} {detail}")
        return response.json() if response.content else {}

    def _github_api_post(self, path: str, json: dict) -> dict:
        url = f"{self._api_base}{path}"
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.post(url, headers=self._headers(), json=json)
        except httpx.HTTPError as exc:
            raise GithubServiceError("GitHub API POST request failed") from exc
        if response.status_code >= 400:
            detail = (response.text or "").strip()[:300]
            raise GithubServiceError(f"GitHub API POST failed: {response.status_code} {detail}")
        return response.json() if response.content else {}

    def _github_api_put(self, path: str, json: dict) -> dict:
        url = f"{self._api_base}{path}"
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.put(url, headers=self._headers(), json=json)
        except httpx.HTTPError as exc:
            raise GithubServiceError("GitHub API PUT request failed") from exc
        if response.status_code >= 400:
            detail = (response.text or "").strip()[:300]
            raise GithubServiceError(f"GitHub API PUT failed: {response.status_code} {detail}")
        return response.json() if response.content else {}

    def create_fix_branch_and_commit(
        self,
        repo_full_name: str,
        base_sha: str,
        file_path: str,
        original_content: str,
        fixed_content: str,
        finding_title: str,
    ) -> dict:
        """
        Creates a new branch with the security fix and returns the branch name.
        """
        import base64

        _ = original_content
        if not str(fixed_content or "").strip():
            raise GithubServiceError("Cannot commit empty fixed content")

        slug = re.sub(r"[^a-z0-9-]+", "-", str(finding_title or "security-fix").lower()).strip("-")
        if not slug:
            slug = "security-fix"
        branch_name = f"repoguard/fix-{slug[:40]}-{str(base_sha or '')[:7]}"

        # Step 2: Create the branch (via GitHub API)
        self._github_api_post(
            f"/repos/{repo_full_name}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": base_sha,
            },
        )

        # Step 3: Get the current file's SHA (required to update it)
        file_info = self._github_api_get(
            f"/repos/{repo_full_name}/contents/{file_path}",
            params={"ref": branch_name},
        )
        file_sha = file_info["sha"]

        # Step 4: Commit the fixed content to the new branch
        encoded_content = base64.b64encode(fixed_content.encode()).decode()
        self._github_api_put(
            f"/repos/{repo_full_name}/contents/{file_path}",
            json={
                "message": f"fix(security): {finding_title}",
                "content": encoded_content,
                "sha": file_sha,
                "branch": branch_name,
            },
        )

        return {"branch": branch_name}

    def post_security_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        findings: list,
        fix_branch: str | None = None,
    ) -> None:
        """Post a security scan summary comment to the PR."""

        # Build the comment body
        lines = ["## 🔒 RepoGuard Security Scan\n"]

        for finding in findings:
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                str(finding.get("severity", "low")).lower(), "⚪"
            )
            lines.append(f"### {severity_emoji} {finding['title']}")
            lines.append(f"**File:** `{finding['file']}` - Line {finding.get('line', '?')}")
            lines.append(f"**Severity:** {str(finding.get('severity', 'unknown')).upper()}")
            if finding.get("fix_description"):
                lines.append(f"**Fix:** {finding['fix_description']}")
            lines.append("")

        if fix_branch:
            lines.append(f"✅ **Auto-fix committed to branch:** `{fix_branch}`")
            lines.append("Review and merge to apply the fix.")

        lines.append("\n---")
        lines.append("*Scanned by [RepoGuard](https://repoguard.dev) ⚡ — Auto-fix security issues in your PRs*")

        comment_body = "\n".join(lines)

        self._github_api_post(
            f"/repos/{repo_full_name}/issues/{int(pr_number)}/comments",
            json={"body": comment_body},
        )

    @staticmethod
    def _format_clone_error(stderr: str) -> str:
        text = str(stderr or "").strip()
        lowered = text.lower()
        if "could not read username" in lowered or "authentication failed" in lowered or "repository not found" in lowered:
            return (
                "Failed to clone repository: repository is private or inaccessible. "
                "Manual scan currently supports public repositories; for private repositories use the GitHub App PR workflow."
            )
        return f"Failed to clone repository: {text}"

    @staticmethod
    def _ensure_github_https_host(url: str) -> None:
        parsed = urlparse(str(url or "").strip())
        if parsed.scheme != "https" or str(parsed.hostname or "").lower() != "github.com":
            raise GithubServiceError("Only public github.com HTTPS URLs are allowed")

    @staticmethod
    def _run_clone(url: str, repo_dir: Path, timeout_seconds: int = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "clone", "--depth", "1", url, str(repo_dir)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

    @staticmethod
    def _repo_parts(repository: str) -> tuple[str, str]:
        value = str(repository or "").strip()
        if "/" not in value:
            raise GithubServiceError("Repository must be in owner/repo format")
        owner, repo = value.split("/", 1)
        owner = owner.strip()
        repo = repo.strip()
        if not owner or not repo:
            raise GithubServiceError("Repository must be in owner/repo format")
        return owner, repo

    @classmethod
    def installation_clone_url(cls, repository: str, installation_token: str) -> str:
        owner, repo = cls._repo_parts(repository)
        token = str(installation_token or "").strip()
        if not token:
            raise GithubServiceError("Missing installation token for GitHub App clone")
        encoded_token = quote(token, safe="")
        return f"https://x-access-token:{encoded_token}@github.com/{owner}/{repo}.git"

    @classmethod
    def normalize_public_repo_url(cls, github_url: str) -> str:
        raw = str(github_url or "").strip()
        if not raw:
            raise GithubServiceError("Invalid GitHub URL. Expected: https://github.com/owner/repo")

        parsed = urlparse(raw)
        if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
            raise GithubServiceError("Only public github.com HTTPS URLs are allowed")

        path = str(parsed.path or "").strip()
        path = re.sub(r"/+$", "", path)
        path = re.sub(r"\.+$", "", path)

        segments = [segment.strip() for segment in path.split("/") if segment.strip()]
        if len(segments) != 2:
            raise GithubServiceError("Invalid GitHub URL. Expected: https://github.com/owner/repo")

        owner, repo = segments
        if owner.endswith(".") or repo.endswith("."):
            raise GithubServiceError("Invalid GitHub URL. Remove trailing punctuation from owner/repo name")

        canonical = f"https://github.com/{owner}/{repo}"
        if not cls.GITHUB_PATTERN.match(canonical):
            raise GithubServiceError("Invalid GitHub URL. Expected: https://github.com/owner/repo")

        return canonical

    @classmethod
    def validate_public_repo_url(cls, github_url: str) -> str:
        return cls.normalize_public_repo_url(github_url)

    @staticmethod
    def clone_repo_temp(github_url: str) -> tuple[Path, Path]:
        github_url = GithubService.normalize_public_repo_url(github_url)
        temp_dir = Path(tempfile.mkdtemp(prefix="ghsaas_"))
        repo_dir = temp_dir / "repo"
        try:
            result = GithubService._run_clone(github_url, repo_dir)
        except FileNotFoundError as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GithubServiceError("git is not installed or not in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GithubServiceError("Repository clone timed out") from exc

        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            stderr = (result.stderr or "").strip()
            raise GithubServiceError(GithubService._format_clone_error(stderr))

        return temp_dir, repo_dir

    @staticmethod
    def clone_repo_temp_from_github_clone_url(clone_url: str) -> tuple[Path, Path]:
        GithubService._ensure_github_https_host(clone_url)
        temp_dir = Path(tempfile.mkdtemp(prefix="ghsaas_"))
        repo_dir = temp_dir / "repo"
        try:
            result = GithubService._run_clone(str(clone_url).strip(), repo_dir)
        except FileNotFoundError as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GithubServiceError("git is not installed or not in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GithubServiceError("Repository clone timed out") from exc

        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GithubServiceError(GithubService._format_clone_error((result.stderr or "").strip()))

        return temp_dir, repo_dir

    @staticmethod
    def clone_repo_temp_with_installation_token(repository: str, installation_token: str) -> tuple[Path, Path]:
        tokenized_url = GithubService.installation_clone_url(repository, installation_token)
        try:
            return GithubService.clone_repo_temp_from_github_clone_url(tokenized_url)
        except GithubServiceError as exc:
            redacted_message = str(exc).replace(str(installation_token or ""), "***")
            raise GithubServiceError(redacted_message) from exc

    @staticmethod
    def _checkout_commit(repo_dir: Path, clone_url: str, commit_sha: str, timeout_seconds: int = 180) -> None:
        sha = str(commit_sha or "").strip()
        if not sha:
            return
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha):
            raise GithubServiceError("Invalid commit SHA")
        try:
            fetch = subprocess.run(
                ["git", "fetch", "--depth", "1", "origin", sha],
                cwd=str(repo_dir),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if fetch.returncode != 0:
                raise GithubServiceError("Failed to fetch PR commit")
            checkout = subprocess.run(
                ["git", "checkout", "--force", sha],
                cwd=str(repo_dir),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if checkout.returncode != 0:
                raise GithubServiceError("Failed to check out PR commit")
        except FileNotFoundError as exc:
            raise GithubServiceError("git is not installed or not in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise GithubServiceError("PR commit checkout timed out") from exc

    @staticmethod
    def clone_repo_temp_with_installation_token_at_commit(
        repository: str, installation_token: str, commit_sha: str
    ) -> tuple[Path, Path]:
        tokenized_url = GithubService.installation_clone_url(repository, installation_token)
        try:
            temp_dir, repo_dir = GithubService.clone_repo_temp_from_github_clone_url(tokenized_url)
        except GithubServiceError as exc:
            redacted_message = str(exc).replace(str(installation_token or ""), "***")
            raise GithubServiceError(redacted_message) from exc
        try:
            GithubService._checkout_commit(repo_dir, tokenized_url, commit_sha)
        except GithubServiceError as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            redacted_message = str(exc).replace(str(installation_token or ""), "***")
            raise GithubServiceError(redacted_message) from exc
        return temp_dir, repo_dir

    @staticmethod
    def cleanup_temp_dir(temp_dir: Path) -> None:
        shutil.rmtree(temp_dir, ignore_errors=True)
