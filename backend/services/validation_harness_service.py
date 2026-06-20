from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from backend.models.scan_model import ValidationRepoResult, ValidationRunResponse
from backend.services.scanner_service import ScannerDependencyError, ScannerService, ScannerServiceError


class ValidationHarnessError(Exception):
    pass


class ValidationHarnessService:
    def __init__(self) -> None:
        self.artifacts_dir = (Path(__file__).resolve().parents[2] / "artifacts" / "validation").resolve()
        self.manifests_dir = (Path(__file__).resolve().parents[2] / "validation").resolve()
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_and_verify_path(self, base_dir: Path, unsafe_path_str: str, context: str) -> Path:
        """Resolves a path and ensures it's safely contained within the base directory."""
        # Sanitize input to prevent null byte injection and other tricks.
        sanitized_path_str = str(unsafe_path_str or "").strip().replace("\x00", "")
        if not sanitized_path_str:
            raise ValidationHarnessError(f"Empty path provided for {context}")

        # This is the crucial step for security. .resolve() canonicalizes the path,
        # eliminating '..', '.', and handling symlinks.
        resolved_path = (base_dir / sanitized_path_str).resolve()

        # After resolving, we perform a containment check. If the resolved path
        # is not inside the secure base directory, relative_to() will raise a ValueError.
        try:
            resolved_path.relative_to(base_dir)
        except ValueError as exc:
            raise ValidationHarnessError(f"Path traversal detected for {context}: {unsafe_path_str}") from exc

        # As an extra precaution, explicitly deny if any part of the path is a symlink.
        # This is belt-and-suspenders, as the resolve() + relative_to() check is very strong.
        if resolved_path.is_symlink() or any(p.is_symlink() for p in resolved_path.parents):
             raise ValidationHarnessError(f"Symlinks are not allowed in {context} paths: {unsafe_path_str}")

        return resolved_path

    def _load_manifest(self, manifest_id: str) -> tuple[Path, list[dict[str, Any]]]:
        manifest_path = self._resolve_and_verify_path(self.manifests_dir, f"{manifest_id}.json", "manifest")

        if not manifest_path.exists():
            raise ValidationHarnessError(f"Manifest '{manifest_id}' not found.")

        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationHarnessError("Manifest is not valid JSON") from exc

        repos = payload.get("repos") if isinstance(payload, dict) else None
        if not isinstance(repos, list) or not repos:
            raise ValidationHarnessError("Manifest must contain a non-empty 'repos' array")
        return manifest_path, repos

    def _load_manifest_from_path(self, manifest_path: Path) -> list[dict[str, Any]]:
        if not manifest_path.exists() or not manifest_path.is_file():
            raise ValidationHarnessError(f"Manifest path does not exist: {manifest_path}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationHarnessError("Manifest is not valid JSON") from exc

        repos = payload.get("repos") if isinstance(payload, dict) else None
        if not isinstance(repos, list) or not repos:
            raise ValidationHarnessError("Manifest must contain a non-empty 'repos' array")
        return repos

    @staticmethod
    def _entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
        try:
            value = int(entry.get(key, default))
            return value if value >= 0 else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _relative_limit(expected_count: int) -> int:
        expected = max(0, int(expected_count or 0))
        if expected == 0:
            return 1
        return max(1, int(round(expected * 0.5)))

    def _run_manifest_repos(self, manifest_path: Path, manifest_ref: str, repos: list[dict[str, Any]], artifacts_dir: Path) -> ValidationRunResponse:

        run_id = uuid4().hex[:12]
        now = datetime.now(timezone.utc)
        results: list[ValidationRepoResult] = []

        for index, entry in enumerate(repos):
            if not isinstance(entry, dict):
                raise ValidationHarnessError(f"Manifest repo entry at index {index} must be an object")

            repo_id = str(entry.get("id") or f"repo-{index + 1}").strip()
            source_path_str = str(entry.get("path") or "").strip()
            if not source_path_str:
                raise ValidationHarnessError(f"Manifest repo '{repo_id}' is missing required field 'path'")

            # Repos are resolved relative to the manifest file's location.
            # The _resolve_and_verify_path function ensures this path is still within the overall validation root.
            resolved_path = self._resolve_and_verify_path(manifest_path.parent, source_path_str, f"repo '{repo_id}'")

            if not resolved_path.exists() or not resolved_path.is_dir():
                raise ValidationHarnessError(f"Repo path does not exist or is not a directory: {resolved_path}")

            expected_issue_count = self._entry_int(entry, "expected_issue_count", 0)
            issue_tolerance = self._entry_int(entry, "issue_tolerance", 0)
            expected_high_count = self._entry_int(entry, "expected_high_count", 0)
            high_tolerance = self._entry_int(entry, "high_tolerance", 0)

            scanner = ScannerService()
            try:
                issues = scanner.scan_repository(resolved_path)
            except (ScannerDependencyError, ScannerServiceError) as exc:
                raise ValidationHarnessError(
                    f"Scanner failed for repo '{repo_id}': {exc}"
                ) from exc
            actual_issue_count = len(issues)
            actual_high_count = sum(1 for issue in issues if str(issue.severity or "").upper() == "HIGH")

            issue_delta = abs(actual_issue_count - expected_issue_count)
            high_delta = abs(actual_high_count - expected_high_count)
            absolute_issue_limit = issue_tolerance
            absolute_high_limit = high_tolerance
            relative_issue_limit = self._relative_limit(expected_issue_count)
            relative_high_limit = self._relative_limit(expected_high_count)

            issue_limit = min(absolute_issue_limit, relative_issue_limit)
            high_limit = min(absolute_high_limit, relative_high_limit)
            passed = issue_delta <= issue_limit and high_delta <= high_limit

            results.append(
                ValidationRepoResult(
                    repo_id=repo_id,
                    repo_path=str(resolved_path),
                    expected_issue_count=expected_issue_count,
                    actual_issue_count=actual_issue_count,
                    issue_tolerance=issue_tolerance,
                    issue_delta=issue_delta,
                    expected_high_count=expected_high_count,
                    actual_high_count=actual_high_count,
                    high_tolerance=high_tolerance,
                    high_delta=high_delta,
                    passed=passed,
                )
            )

        results.sort(key=lambda item: item.repo_id)
        passed_repos = sum(1 for item in results if item.passed)
        total_repos = len(results)
        failed_repos = total_repos - passed_repos

        payload = {
            "run_id": run_id,
            "generated_at": now.isoformat(),
            "manifest_path": manifest_ref,
            "total_repos": total_repos,
            "passed_repos": passed_repos,
            "failed_repos": failed_repos,
            "results": [r.model_dump() for r in results],
        }

        artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifacts_dir / f"{now.strftime('%Y%m%d-%H%M%S')}-{run_id}.json"
        artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        payload["artifact_path"] = str(artifact_path)

        return ValidationRunResponse.model_validate(payload)

    def run_manifest(self, manifest_id: str) -> ValidationRunResponse:
        manifest_path, repos = self._load_manifest(manifest_id)
        return self._run_manifest_repos(manifest_path, manifest_id, repos, self.artifacts_dir)

    def run_manifest_path(self, manifest_path: str, output_dir: str | None = None) -> ValidationRunResponse:
        resolved_manifest = Path(str(manifest_path or "").strip()).expanduser().resolve()
        repos = self._load_manifest_from_path(resolved_manifest)
        artifacts_dir = self.artifacts_dir if not output_dir else Path(str(output_dir).strip()).expanduser().resolve()
        return self._run_manifest_repos(resolved_manifest, str(resolved_manifest), repos, artifacts_dir)

    def latest_artifact(self, manifest_id: str | None, output_dir: str | None = None) -> dict[str, Any] | None:
        artifacts_dir = self.artifacts_dir if not output_dir else Path(str(output_dir).strip()).expanduser().resolve()
        if not artifacts_dir.exists():
            return None

        all_artifacts = list(artifacts_dir.glob("*.json"))
        if not all_artifacts:
            return None

        # Filter by manifest_id if provided
        if manifest_id:
            candidates = []
            for artifact_path in all_artifacts:
                try:
                    data = json.loads(artifact_path.read_text(encoding="utf-8"))
                    if data.get("manifest_path") == manifest_id:
                        candidates.append(artifact_path)
                except (json.JSONDecodeError, KeyError):
                    continue
            if not candidates:
                return None
            all_artifacts = candidates

        latest_file = max(all_artifacts, key=lambda p: p.stat().st_mtime)

        try:
            payload = json.loads(latest_file.read_text(encoding="utf-8"))
            # Add the absolute path back into the payload for the response.
            payload["artifact_path"] = str(latest_file)
            return payload
        except (json.JSONDecodeError, KeyError):
            return None


validation_harness_service = ValidationHarnessService()
