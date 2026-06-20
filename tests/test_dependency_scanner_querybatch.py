from pathlib import Path

from backend.services.dependency_scanner import DependencyEntry, DependencyScanner


class _FakeResponse:
    def __init__(self, status_code: int, data: dict):
        self.status_code = status_code
        self._data = data
        self.content = b"{}"

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json):
        self.calls.append((url, json))
        assert url.endswith("/querybatch")
        assert len(json["queries"]) == 2
        return _FakeResponse(
            200,
            {
                "results": [
                    {"vulns": [{"id": "OSV-1", "aliases": ["CVE-1"], "database_specific": {"severity": "HIGH"}}]},
                    {"vulns": []},
                ]
            },
        )


def test_querybatch_deduplicates_dependencies(monkeypatch, tmp_path: Path) -> None:
    scanner = DependencyScanner()
    deps = [
        DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json"),
        DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package-lock.json"),
        DependencyEntry(ecosystem="npm", name="express", version="4.17.1", manifest_path="package.json"),
    ]

    fake_client = _FakeClient()
    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", lambda timeout: fake_client)

    results = scanner._query_osv_for_dependencies(deps)

    assert len(results) == 3
    lodash_results = [v for dep, v in results if dep.name == "lodash"]
    express_results = [v for dep, v in results if dep.name == "express"]
    assert len(lodash_results) == 2
    assert len(lodash_results[0]) == 1
    assert len(express_results[0]) == 0
