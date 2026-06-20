from backend.services.dependency_scanner import DependencyEntry, DependencyScanner
from pathlib import Path
import json


def test_osv_query_uses_cache(monkeypatch) -> None:
    scanner = DependencyScanner(ttl_seconds=900)
    dep = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json")

    calls = {"count": 0}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {
                "vulns": [
                    {
                        "id": "OSV-123",
                        "aliases": ["CVE-2020-8203"],
                        "summary": "Prototype pollution",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                    }
                ]
            }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url: str, json: dict):
            calls["count"] += 1
            assert url == DependencyScanner.OSV_URL
            assert json["package"]["name"] == "lodash"
            assert json["package"]["ecosystem"] == "npm"
            assert json["version"] == "4.17.15"
            return FakeResponse()

    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", FakeClient)

    first = scanner._query_osv(dep)
    second = scanner._query_osv(dep)

    assert calls["count"] == 1
    assert len(first) == 1
    assert second == first


def test_scan_queries_osv_for_each_dependency(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"placeholder":"1.0.0"}}', encoding="utf-8")

    scanner = DependencyScanner()
    deps = [
        DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json"),
        DependencyEntry(ecosystem="npm", name="axios", version="1.6.0", manifest_path="package-lock.json"),
    ]

    monkeypatch.setattr(scanner, "_collect_dependencies", lambda _: deps)

    query_calls: list[tuple[str, str]] = []

    def fake_query_batch(items: list[DependencyEntry]):
        for dep in items:
            query_calls.append((dep.name, dep.version))

        results = []
        for dep in items:
            if dep.name == "lodash":
                results.append(
                    (
                        dep,
                        [
                            {
                                "id": "OSV-123",
                                "aliases": ["CVE-2020-8203"],
                                "summary": "Prototype pollution",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                            }
                        ],
                    )
                )
            else:
                results.append((dep, []))
        return results

    monkeypatch.setattr(scanner, "_query_osv_for_dependencies", fake_query_batch)

    findings = scanner.scan(tmp_path)

    assert query_calls == [("lodash", "4.17.15"), ("axios", "1.6.0")]
    assert len(findings) == 1
    assert findings[0]["package"] == "lodash"
    assert findings[0]["cve"] == "CVE-2020-8203"


def test_normalize_finding_extracts_cve_severity_and_fix() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json")
    vuln = {
        "id": "OSV-123",
        "aliases": ["CVE-2020-8203"],
        "summary": "Prototype pollution",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])

    assert finding["type"] == "dependency_vuln"
    assert finding["severity"] == "HIGH"
    assert finding["package"] == "lodash"
    assert finding["version"] == "4.17.15"
    assert finding["cve"] == "CVE-2020-8203"
    assert finding["fix"] == "Upgrade to 4.17.21"
    assert finding["line"] == 1
    assert finding["confidence"] == 100
    assert finding["confidence_label"] == "HIGH"


def test_normalize_finding_classifies_impact_rce() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json")
    vuln = {
        "id": "OSV-1",
        "aliases": ["CVE-2020-8203"],
        "summary": "Remote code execution in parser",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "RCE"
    assert finding["impact_label"] == "Remote Code Execution (RCE)"


def test_normalize_finding_classifies_impact_dos() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="1.0.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-2",
        "aliases": ["CVE-2024-2001"],
        "summary": "Denial of service via malformed payload",
        "database_specific": {"severity": "MEDIUM"},
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.2"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "DoS"
    assert finding["impact_label"] == "Denial of Service (DoS)"


def test_normalize_finding_classifies_impact_data_leak() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="1.0.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-3",
        "aliases": ["CVE-2024-2002"],
        "summary": "Sensitive data exposure in debug logs",
        "database_specific": {"severity": "MEDIUM"},
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.3"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "Data Leak"
    assert finding["impact_label"] == "Sensitive Information Exposure (Data Leak)"


def test_normalize_finding_classifies_impact_auth_bypass() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="1.0.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-4",
        "aliases": ["CVE-2024-2003"],
        "summary": "Authentication bypass in token validation",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.4"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "Auth Bypass"
    assert finding["impact_label"] == "Authentication Bypass (Auth Bypass)"


def test_normalize_finding_classifies_impact_injection() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="1.0.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-5",
        "aliases": ["CVE-2024-2004"],
        "summary": "Command injection in helper",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.5"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "Injection"
    assert finding["impact_label"] == "Injection"


def test_normalize_finding_classifies_impact_unknown() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="1.0.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-6",
        "aliases": ["CVE-2024-2005"],
        "summary": "Unexpected parser behavior",
        "database_specific": {"severity": "LOW"},
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.6"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["impact_category"] == "Unknown"
    assert finding["impact_label"] == "Unknown"


def test_invalid_package_json_and_null_dependency_versions_do_not_crash(tmp_path: Path) -> None:
    broken = tmp_path / "package.json"
    broken.write_text("{this is invalid json", encoding="utf-8")

    scanner = DependencyScanner()
    assert scanner._parse_package_json(broken, tmp_path) == []

    valid = tmp_path / "valid-package.json"
    valid.write_text(
        json.dumps({"dependencies": {"lodash": None, "axios": "1.6.0"}}),
        encoding="utf-8",
    )
    parsed = scanner._parse_package_json(valid, tmp_path)
    assert len(parsed) == 1
    assert parsed[0].name == "axios"


def test_requirements_mixed_formats_keep_only_normalized_entries(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(
        "flask==2.0.0\nrequests>=2.25\ngit+https://github.com/acme/pkg.git\n# comment\ninvalid_line\n",
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_requirements(req, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("flask", "2.0.0") in keys
    assert ("requests", "2.25") in keys
    assert all(name != "invalid_line" for name, _ in keys)
    line_map = {dep.name: dep.line for dep in parsed}
    assert line_map["flask"] == 1
    assert line_map["requests"] == 2


def test_requirements_parses_extras_and_markers(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(
        "uvicorn[standard]==0.34.0; python_version >= '3.10'\nflask ~= 2.3.2\n",
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_requirements(req, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("uvicorn", "0.34.0") in keys
    assert ("flask", "2.3.2") in keys


def test_parse_pyproject_supports_pep621_and_poetry(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "fastapi>=0.115.12",
  "httpx==0.28.1",
]

[tool.poetry.dependencies]
python = ">=3.11,<4.0"
pydantic = "^2.11.3"
uvicorn = {version = "0.34.0"}
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_pyproject(pyproject, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("fastapi", "0.115.12") in keys
    assert ("httpx", "0.28.1") in keys
    assert ("pydantic", "2.11.3") in keys
    assert ("uvicorn", "0.34.0") in keys


def test_severity_falls_back_to_cvss_score_when_database_specific_missing() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="PyPI", name="demo", version="1.0.0", manifest_path="requirements.txt")
    vuln = {
        "id": "OSV-123",
        "aliases": ["CVE-2025-1111"],
        "summary": "demo vuln",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.2"}]}]}],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["severity"] == "HIGH"


def test_parse_package_lock_collects_dependencies(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {
                    "lodash": {"version": "4.17.21"},
                },
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/axios": {"version": "1.6.8"},
                },
            }
        ),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_package_lock(lock, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("lodash", "4.17.21") in keys
    assert ("axios", "1.6.8") in keys


def test_parse_package_json_handles_npm_alias_and_workspace_specs(tmp_path: Path) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "my-axios": "npm:axios@~1.6.8",
                    "local-lib": "file:../local-lib",
                    "shared-ui": "workspace:*",
                },
                "devDependencies": {
                    "typescript": "~5.4.5",
                },
            }
        ),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_package_json(manifest, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("lodash", "4.17.21") in keys
    assert ("axios", "1.6.8") in keys
    assert ("typescript", "5.4.5") in keys
    assert all(name != "local-lib" for name, _ in keys)
    assert all(name != "shared-ui" for name, _ in keys)


def test_parse_package_lock_skips_root_project_entry(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "name": "demo",
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.21"},
                },
            }
        ),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_package_lock(lock, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("lodash", "4.17.21") in keys
    assert ("demo", "1.0.0") not in keys


def test_exploitability_profile_scores_high_with_public_network_noauth_lowcomplex() -> None:
    scanner = DependencyScanner()
    vulnerabilities = [
        {
            "references": [
                {"type": "EXPLOIT", "url": "https://www.exploit-db.com/exploits/12345"},
            ],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ],
        }
    ]

    profile = scanner._exploitability_profile(vulnerabilities)

    assert profile["public_exploit"] is True
    assert profile["network_access"] is True
    assert profile["auth_required"] is False
    assert profile["low_complexity"] is True
    assert profile["score"] == 9
    assert profile["level"] == "HIGH"
    assert "Public exploit available" in profile["reasons"]


def test_exploitability_profile_scores_low_without_signals() -> None:
    scanner = DependencyScanner()
    vulnerabilities = [
        {
            "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/OSV-1"}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"}],
        }
    ]

    profile = scanner._exploitability_profile(vulnerabilities)

    assert profile["public_exploit"] is False
    assert profile["network_access"] is False
    assert profile["auth_required"] is True
    assert profile["low_complexity"] is False
    assert profile["score"] == 0
    assert profile["level"] == "LOW"


def test_parse_yarn_lock_collects_versions(tmp_path: Path) -> None:
    yarn = tmp_path / "yarn.lock"
    yarn.write_text(
        'lodash@^4.17.0:\n  version "4.17.21"\n\n"@types/node@^20.0.0":\n  version "20.11.30"\n',
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_yarn_lock(yarn, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("lodash", "4.17.21") in keys
    assert ("@types/node", "20.11.30") in keys


def test_parse_pnpm_lock_collects_versions(tmp_path: Path) -> None:
    pnpm = tmp_path / "pnpm-lock.yaml"
    pnpm.write_text(
        """
lockfileVersion: '9.0'
packages:
  /axios@1.7.1:
    resolution: {integrity: sha512-...}
  /@types/node@20.11.30:
    resolution: {integrity: sha512-...}
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_pnpm_lock(pnpm, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("axios", "1.7.1") in keys
    assert ("@types/node", "20.11.30") in keys


def test_parse_gradle_collects_maven_coordinates(tmp_path: Path) -> None:
    gradle = tmp_path / "build.gradle"
    gradle.write_text(
        """
dependencies {
  implementation 'org.springframework:spring-web:6.1.5'
  testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_gradle(gradle, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("org.springframework:spring-web", "6.1.5") in keys
    assert ("org.junit.jupiter:junit-jupiter", "5.10.2") in keys


def test_parse_go_mod_collects_require_versions(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
module example.com/demo

go 1.22

require (
    github.com/gin-gonic/gin v1.10.0
    golang.org/x/crypto v0.25.0 // indirect
)

require github.com/sirupsen/logrus v1.9.3
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_go_mod(go_mod, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("github.com/gin-gonic/gin", "v1.10.0") in keys
    assert ("golang.org/x/crypto", "v0.25.0") in keys
    assert ("github.com/sirupsen/logrus", "v1.9.3") in keys


def test_parse_csproj_collects_package_reference_versions(tmp_path: Path) -> None:
    csproj = tmp_path / "demo.csproj"
    csproj.write_text(
        """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_csproj(csproj, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("Newtonsoft.Json", "13.0.3") in keys
    assert ("Serilog", "3.1.1") in keys


def test_parse_packages_config_collects_nuget_packages(tmp_path: Path) -> None:
    cfg = tmp_path / "packages.config"
    cfg.write_text(
        """
<packages>
  <package id="NUnit" version="3.13.3" targetFramework="net48" />
  <package id="Moq" version="4.20.70" targetFramework="net48" />
</packages>
""".strip(),
        encoding="utf-8",
    )

    scanner = DependencyScanner()
    parsed = scanner._parse_packages_config(cfg, tmp_path)
    keys = {(dep.name, dep.version) for dep in parsed}

    assert ("NUnit", "3.13.3") in keys
    assert ("Moq", "4.20.70") in keys


def test_osv_query_maps_go_and_nuget_ecosystems(monkeypatch) -> None:
    scanner = DependencyScanner(ttl_seconds=900)
    seen_payloads: list[dict] = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"vulns": []}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url: str, json: dict):
            seen_payloads.append(json)
            return FakeResponse()

    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", FakeClient)

    scanner._query_osv(DependencyEntry(ecosystem="Go", name="github.com/gin-gonic/gin", version="v1.10.0", manifest_path="go.mod"))
    scanner._query_osv(DependencyEntry(ecosystem="NuGet", name="Newtonsoft.Json", version="13.0.3", manifest_path="demo.csproj"))

    ecosystems = [payload["package"]["ecosystem"] for payload in seen_payloads]
    assert "Go" in ecosystems
    assert "NuGet" in ecosystems


def test_malformed_pom_does_not_crash(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text("<project><dependencies><dependency>", encoding="utf-8")

    scanner = DependencyScanner()
    assert scanner._parse_pom(pom, tmp_path) == []


def test_osv_cache_expires_after_ttl(monkeypatch) -> None:
    scanner = DependencyScanner(ttl_seconds=1)
    dep = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json")

    calls = {"count": 0}
    clock = {"now": 1000.0}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"vulns": []}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url: str, json: dict):
            calls["count"] += 1
            return FakeResponse()

    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", FakeClient)
    monkeypatch.setattr("backend.services.dependency_scanner.time.time", lambda: clock["now"])

    scanner._query_osv(dep)
    clock["now"] = 1000.5
    scanner._query_osv(dep)
    clock["now"] = 1002.0
    scanner._query_osv(dep)

    assert calls["count"] == 2


def test_osv_cache_key_isolated_by_version(monkeypatch) -> None:
    scanner = DependencyScanner(ttl_seconds=900)
    dep_a = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.15", manifest_path="package.json")
    dep_b = DependencyEntry(ecosystem="npm", name="lodash", version="4.17.21", manifest_path="package.json")

    calls = {"count": 0}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"vulns": []}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url: str, json: dict):
            calls["count"] += 1
            return FakeResponse()

    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", FakeClient)

    scanner._query_osv(dep_a)
    scanner._query_osv(dep_b)
    scanner._query_osv(dep_a)

    assert calls["count"] == 2


def test_fixed_version_prefers_stable_minimum_higher_release() -> None:
    scanner = DependencyScanner()
    dep = DependencyEntry(ecosystem="npm", name="demo", version="20.1.0", manifest_path="package.json")
    vuln = {
        "id": "OSV-456",
        "aliases": ["CVE-2026-0001"],
        "summary": "demo vuln",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "20.0.0"},
                            {"fixed": "21.0.0-rc.0"},
                            {"fixed": "21.0.2"},
                            {"fixed": "22.0.0-next.3"},
                        ]
                    }
                ]
            }
        ],
    }

    finding = scanner._normalize_finding(dep, [vuln])
    assert finding["fix_version"] == "21.0.2"
    assert finding["fix"] == "Upgrade to 21.0.2"


def test_scan_aggregates_multiple_vulns_per_dependency(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"multer":"1.4.5-lts.1"}}', encoding="utf-8")

    scanner = DependencyScanner()

    class FakeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json() -> dict:
            return {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "OSV-A",
                                "aliases": ["CVE-2025-0001"],
                                "summary": "First issue",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
                            },
                            {
                                "id": "OSV-B",
                                "aliases": ["CVE-2025-0002"],
                                "summary": "Second issue",
                                "database_specific": {"severity": "MEDIUM"},
                                "affected": [{"ranges": [{"events": [{"fixed": "2.0.2"}]}]}],
                            },
                        ]
                    }
                ]
            }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url: str, json: dict):
            assert url == DependencyScanner.OSV_BATCH_URL
            assert len(json.get("queries") or []) == 1
            return FakeResponse()

    monkeypatch.setattr("backend.services.dependency_scanner.httpx.Client", FakeClient)

    findings = scanner.scan(tmp_path)
    assert len(findings) == 1
    assert findings[0]["package"] == "multer"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["cve"] == "CVE-2025-0001"
    assert "2 known vulnerabilities" in findings[0]["issue"]
    assert findings[0]["fix_version"] == "2.0.0"
