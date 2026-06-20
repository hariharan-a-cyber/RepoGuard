import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.services.auth_service import auth_service
from backend.services.feedback_service import feedback_service
from backend.services.metrics_service import metrics_service
from backend.services.scanner_service import ScannerService


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reset_state() -> None:
    auth_service._users.clear()
    auth_service._sessions.clear()
    auth_service._scan_events.clear()
    auth_service._audit_unlocks.clear()

    feedback_service._items.clear()
    metrics_service._events.clear()


def _mk_issue(severity: str, file_name: str) -> SecurityIssue:
    return SecurityIssue(
        title=f"[{severity}] synthetic finding",
        severity=severity,
        file=file_name,
        line=4,
        scanner="regex",
        rule_id="regex.synthetic",
        message="synthetic",
        category="SQL Injection" if severity == "HIGH" else "Weak Input Validation",
        evidence="db.query(userInput)",
        data_source="user_input",
        usage_context="database",
        guidance=AIGuidance(
            explanation="x",
            danger="y",
            real_world_example="z",
            exact_fix="Before:\nold\n\nAfter:\nnew",
        ),
    )


def test_metrics_export_json_and_csv() -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "kpi@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    metrics_service.record(email="kpi@example.com", event="scan_started", scan_id="s-1")
    metrics_service.record(email="kpi@example.com", event="scan_started", scan_id="s-2")
    metrics_service.record(email="kpi@example.com", event="scan_completed", scan_id="s-1")
    metrics_service.record(email="kpi@example.com", event="unlock_clicked", scan_id="s-1")
    metrics_service.record(email="kpi@example.com", event="audit_unlocked", scan_id="s-1")
    metrics_service.record(email="kpi@example.com", event="scan_started", scan_id="legacy")
    metrics_service._events[-1].created_at = datetime.now(timezone.utc) - timedelta(days=8)

    export_json = client.get("/metrics/export.json", headers=_auth_header(token))
    assert export_json.status_code == 200
    payload = export_json.json()
    assert payload["cohort"]["scans_started"] == 3
    assert payload["cohort"]["scans_completed"] == 1
    assert payload["cohort_24h"]["scans_started"] == 2
    assert payload["cohort_7d"]["scans_started"] == 2
    assert payload["completion_rate"] == 33.33
    assert payload["completion_rate_24h"] == 50.0
    assert payload["completion_rate_7d"] == 50.0
    assert payload["unlock_click_through_rate"] == 100.0
    assert payload["unlock_click_through_rate_24h"] == 100.0
    assert payload["unlock_click_through_rate_7d"] == 100.0
    assert payload["unlock_conversion_rate"] == 100.0
    assert payload["unlock_conversion_rate_24h"] == 100.0
    assert payload["unlock_conversion_rate_7d"] == 100.0
    export_csv = client.get("/metrics/export.csv", headers=_auth_header(token))
    assert export_csv.status_code == 200
    assert "text/csv" in export_csv.headers.get("content-type", "")
    assert "completion_rate_24h" in export_csv.text
    assert "events_7d" in export_csv.text
    assert "50.00" in export_csv.text


def test_validation_run_uses_manifest_tolerances_and_writes_artifact(tmp_path: Path, monkeypatch) -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "validate@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    repo_pass = tmp_path / "repo-pass"
    repo_fail = tmp_path / "repo-fail"
    repo_pass.mkdir(parents=True, exist_ok=True)
    repo_fail.mkdir(parents=True, exist_ok=True)

    manifest_path = tmp_path / "manifest.json"
    manifest_payload = {
        "repos": [
            {
                "id": "repo-pass",
                "path": "repo-pass",
                "expected_issue_count": 2,
                "issue_tolerance": 0,
                "expected_high_count": 1,
                "high_tolerance": 0,
            },
            {
                "id": "repo-fail",
                "path": "repo-fail",
                "expected_issue_count": 1,
                "issue_tolerance": 0,
                "expected_high_count": 0,
                "high_tolerance": 0,
            },
        ]
    }
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

    def fake_scan_repository(self, repo_dir: Path):
        name = Path(repo_dir).name
        if name == "repo-pass":
            return [_mk_issue("HIGH", "a.py"), _mk_issue("LOW", "b.py")]
        return [_mk_issue("HIGH", "c.py"), _mk_issue("LOW", "d.py")]

    monkeypatch.setattr(ScannerService, "scan_repository", fake_scan_repository)

    response = client.post(
        "/validation/run",
        headers=_auth_header(token),
        json={
            "manifest_path": str(manifest_path),
            "output_dir": str(tmp_path / "artifacts"),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_repos"] == 2
    assert payload["passed_repos"] == 1
    assert payload["failed_repos"] == 1
    assert len(payload["results"]) == 2

    artifact_path = Path(payload["artifact_path"])
    assert artifact_path.exists()
    artifact_data = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact_data["total_repos"] == 2
    assert artifact_data["failed_repos"] == 1


def test_validation_latest_endpoint_returns_latest_artifact(tmp_path: Path, monkeypatch) -> None:
    _reset_state()

    register = client.post("/auth/register", json={"email": "latest@example.com", "password": "StrongPass1!"})
    assert register.status_code == 200
    token = register.json()["token"]

    repo_dir = tmp_path / "repo-latest"
    repo_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = tmp_path / "manifest-latest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "repos": [
                    {
                        "id": "repo-latest",
                        "path": "repo-latest",
                        "expected_issue_count": 1,
                        "issue_tolerance": 0,
                        "expected_high_count": 1,
                        "high_tolerance": 0,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(ScannerService, "scan_repository", lambda self, repo_path: [_mk_issue("HIGH", "latest.py")])

    run_response = client.post(
        "/validation/run",
        headers=_auth_header(token),
        json={
            "manifest_path": str(manifest_path),
            "output_dir": str(tmp_path / "artifacts"),
        },
    )
    assert run_response.status_code == 200

    latest = client.get(
        "/validation/latest",
        headers=_auth_header(token),
        params={"output_dir": str(tmp_path / "artifacts")},
    )
    assert latest.status_code == 200
    payload = latest.json()
    assert payload["run_id"] == run_response.json()["run_id"]
    assert payload["total_repos"] == 1
    assert payload["passed_repos"] == 1
    assert payload["failed_repos"] == 0
    assert Path(payload["artifact_path"]).exists()
