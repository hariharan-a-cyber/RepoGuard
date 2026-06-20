from datetime import datetime, timezone
from pathlib import Path

from backend.services.github_service import GithubService
from backend.services.webhook_queue_service import WebhookQueueJob
from backend.services.webhook_worker_service import WebhookWorkerService


def test_create_fix_branch_and_commit_calls_github_content_update(monkeypatch) -> None:
    service = GithubService(api_token="token")
    calls = {"post": [], "get": [], "put": []}

    def fake_post(path: str, json: dict):
        calls["post"].append((path, json))
        return {}

    def fake_get(path: str, params: dict | None = None):
        calls["get"].append((path, params))
        return {"sha": "file-sha-1"}

    def fake_put(path: str, json: dict):
        calls["put"].append((path, json))
        return {}

    monkeypatch.setattr(service, "_github_api_post", fake_post)
    monkeypatch.setattr(service, "_github_api_get", fake_get)
    monkeypatch.setattr(service, "_github_api_put", fake_put)

    result = service.create_fix_branch_and_commit(
        repo_full_name="acme/widget",
        base_sha="abc123def456",
        file_path="src/user.js",
        original_content="eval(payload)",
        fixed_content="JSON.parse(payload)",
        finding_title="Dangerous eval usage",
    )

    assert result["branch"].startswith("repoguard/fix-")
    assert calls["post"][0][0] == "/repos/acme/widget/git/refs"
    assert calls["get"][0][0] == "/repos/acme/widget/contents/src/user.js"
    assert calls["put"][0][0] == "/repos/acme/widget/contents/src/user.js"


def test_post_security_comment_builds_structured_comment(monkeypatch) -> None:
    service = GithubService(api_token="token")
    captured = {}

    def fake_post(path: str, json: dict):
        captured["path"] = path
        captured["body"] = json.get("body", "")
        return {}

    monkeypatch.setattr(service, "_github_api_post", fake_post)

    service.post_security_comment(
        repo_full_name="acme/widget",
        pr_number=7,
        findings=[
            {
                "title": "SQL Injection",
                "file": "src/user.js",
                "line": 45,
                "severity": "high",
                "fix_description": "Use parameterized query",
            }
        ],
        fix_branch="repoguard/fix-sql-abc1234",
    )

    assert captured["path"] == "/repos/acme/widget/issues/7/comments"
    assert "RepoGuard Security Scan" in captured["body"]
    assert "SQL Injection" in captured["body"]
    assert "Auto-fix committed to branch" in captured["body"]
    assert "*Scanned by [RepoGuard](https://repoguard.dev) ⚡ — Auto-fix security issues in your PRs*" in captured["body"]


def test_worker_apply_auto_fix_and_comment_uses_fix_code(monkeypatch, tmp_path: Path) -> None:
    worker = WebhookWorkerService()

    repo_root = tmp_path / "repo"
    repo_root.mkdir(parents=True)
    source_file = repo_root / "src" / "user.js"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("const payload = req.query.x; eval(payload);\n", encoding="utf-8")

    temp_dir = tmp_path / "temp"
    temp_dir.mkdir(parents=True)

    monkeypatch.setattr(
        GithubService,
        "clone_repo_temp_from_github_clone_url",
        staticmethod(lambda _url: (temp_dir, repo_root)),
    )
    monkeypatch.setattr(GithubService, "cleanup_temp_dir", staticmethod(lambda _d: None))

    committed = {}

    def fake_commit(self, **kwargs):
        committed["file_path"] = kwargs["file_path"]
        committed["fixed_content"] = kwargs["fixed_content"]
        return {"branch": "repoguard/fix-dangerous-eval-abc1234"}

    def fake_comment(self, **kwargs):
        committed["comment_pr"] = kwargs["pr_number"]

    monkeypatch.setattr(GithubService, "create_fix_branch_and_commit", fake_commit)
    monkeypatch.setattr(GithubService, "post_security_comment", fake_comment)

    findings = [
        {
            "title": "Dangerous eval/exec usage",
            "file": "src/user.js",
            "line": 1,
            "snippet": "const payload = req.query.x; eval(payload);",
            "severity": "high",
            "type": "dangerous_eval",
            "fix_code": "const payload = req.query.x; JSON.parse(payload);",
            "fix_description": "Replace eval with safe parser",
        }
    ]

    branch = worker._apply_auto_fix_and_comment(
        token="token",
        repository="acme/widget",
        commit_sha="abc123def",
        pr_number=9,
        repo_url="https://github.com/acme/widget.git",
        findings=findings,
    )

    assert branch == "repoguard/fix-dangerous-eval-abc1234"
    assert committed["file_path"] == "src/user.js"
    assert "JSON.parse" in committed["fixed_content"]
    assert committed["comment_pr"] == 9


def test_extract_pr_number_from_job_payload() -> None:
    worker = WebhookWorkerService()
    job = WebhookQueueJob(
        job_id="j1",
        queued_at=datetime.now(timezone.utc),
        delivery_id="d1",
        event="pull_request",
        action="opened",
        repository="acme/widget",
        commit_sha="abc",
        installation_id=1,
        payload={"pull_request": {"number": 42}},
    )

    assert worker._extract_pr_number(job) == 42


def test_worker_apply_autofix_uses_prepopulated_fix_code(monkeypatch, tmp_path: Path) -> None:
    worker = WebhookWorkerService()

    repo_root = tmp_path / "repo"
    repo_root.mkdir(parents=True)
    source_file = repo_root / "src" / "user.js"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("const q = 'SELECT * FROM users WHERE id=' + userId;\n", encoding="utf-8")

    temp_dir = tmp_path / "temp"
    temp_dir.mkdir(parents=True)

    monkeypatch.setattr(
        GithubService,
        "clone_repo_temp_from_github_clone_url",
        staticmethod(lambda _url: (temp_dir, repo_root)),
    )
    monkeypatch.setattr(GithubService, "cleanup_temp_dir", staticmethod(lambda _d: None))

    captured = {}

    def fake_commit(self, **kwargs):
        captured["fixed_content"] = kwargs["fixed_content"]
        return {"branch": "repoguard/fix-sql-abc1234"}

    def fake_comment(self, **kwargs):
        captured["findings"] = kwargs["findings"]

    monkeypatch.setattr(GithubService, "create_fix_branch_and_commit", fake_commit)
    monkeypatch.setattr(GithubService, "post_security_comment", fake_comment)

    findings = [
        {
            "title": "SQL Injection",
            "file": "src/user.js",
            "line": 1,
            "snippet": "'SELECT * FROM users WHERE id=' + userId",
            "severity": "high",
            "type": "sql_injection",
            "fix_code": "db.query('SELECT * FROM table WHERE id = ?', [userInput])",
            "fix_description": "Use parameterized queries instead of string concatenation to prevent SQL injection.",
        }
    ]

    branch = worker._apply_auto_fix_and_comment(
        token="token",
        repository="acme/widget",
        commit_sha="abc123def",
        pr_number=9,
        repo_url="https://github.com/acme/widget.git",
        findings=findings,
    )

    assert branch == "repoguard/fix-sql-abc1234"
    assert "db.query('SELECT * FROM table WHERE id = ?', [userInput])" in captured["fixed_content"]
    assert captured["findings"][0]["fix_description"] == (
        "Use parameterized queries instead of string concatenation to prevent SQL injection."
    )
