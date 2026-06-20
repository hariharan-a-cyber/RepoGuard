from pathlib import Path

from backend.services.scanner_service import ScannerService


def test_detect_frameworks_from_python_dependencies(tmp_path: Path) -> None:
    repo = tmp_path / "repo_py"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "requirements.txt").write_text("fastapi==0.115.0\nuvicorn==0.30.0\n", encoding="utf-8")

    detected = ScannerService._detect_frameworks_from_repo(repo, taint_flows=[])
    assert "fastapi" in detected


def test_detect_frameworks_from_node_package_json(tmp_path: Path) -> None:
    repo = tmp_path / "repo_node"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "package.json").write_text(
        '{"name":"x","version":"1.0.0","dependencies":{"express":"^4.18.2"}}',
        encoding="utf-8",
    )

    detected = ScannerService._detect_frameworks_from_repo(repo, taint_flows=[])
    assert "express" in detected


def test_detect_frameworks_from_source_imports(tmp_path: Path) -> None:
    repo = tmp_path / "repo_source"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")

    detected = ScannerService._detect_frameworks_from_repo(repo, taint_flows=[])
    assert "flask" in detected
