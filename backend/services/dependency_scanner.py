import json
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

try:
    import tomllib
except Exception:  # pragma: no cover
    tomllib = None


KNOWN_FIX_VERSIONS = {
    "npm": {
        "express": "4.18.2",
        "lodash": "4.17.21",
        "axios": "1.6.0",
        "jsonwebtoken": "9.0.0",
        "sqlite3": "5.1.7",
        "mysql": "2.18.1",
    },
    "pypi": {
        "flask": "3.0.0",
        "django": "4.2.7",
        "pyyaml": "6.0.1",
        "pillow": "10.1.0",
        "cryptography": "41.0.5",
        "requests": "2.31.0",
    },
}


@dataclass(frozen=True)
class DependencyEntry:
    ecosystem: str
    name: str
    version: str
    manifest_path: str
    line: int = 1


class DependencyScanner:
    OSV_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    IMPACT_LABELS = {
        "RCE": "Remote Code Execution (RCE)",
        "Data Leak": "Sensitive Information Exposure (Data Leak)",
        "DoS": "Denial of Service (DoS)",
        "Auth Bypass": "Authentication Bypass (Auth Bypass)",
        "Injection": "Injection",
        "Unknown": "Unknown",
    }

    def __init__(self, ttl_seconds: int = 900, timeout_seconds: int = 8) -> None:
        self.ttl_seconds = ttl_seconds
        self.timeout_seconds = timeout_seconds
        self._cache: Dict[str, Tuple[float, List[dict]]] = {}
        self._osv_circuit_open_until = 0.0
        self._osv_circuit_latency_threshold = float(str(os.getenv("OSV_CIRCUIT_LATENCY_THRESHOLD_SECONDS", "3.0")).strip() or "3.0")
        self._osv_circuit_cooldown_seconds = int(str(os.getenv("OSV_CIRCUIT_COOLDOWN_SECONDS", "60")).strip() or "60")
        self._max_dependencies = max(1, int(str(os.getenv("OSV_MAX_DEPENDENCIES", "200")).strip() or "200"))
        self.last_dependency_total = 0
        self.last_truncated_count = 0

    def _detect_project_type(self, repo_dir: Path):
        """Detect whether this is a Node.js or Python project."""
        files = [f.name for f in repo_dir.rglob("*") if f.is_file()]
        if "package.json" in files:
            return "node"
        if "requirements.txt" in files or "pyproject.toml" in files or "Pipfile" in files:
            return "python"
        return None

    def scan(self, repo_dir: Path) -> List[dict]:
        project_type = self._detect_project_type(repo_dir)
        if project_type is None:
            return []   # Not a supported project type

        dependencies = self._collect_dependencies(repo_dir)
        self.last_dependency_total = len(dependencies)
        self.last_truncated_count = 0
        if not dependencies:
            return []

        if len(dependencies) > self._max_dependencies:
            self.last_truncated_count = len(dependencies) - self._max_dependencies
            dependencies = dependencies[: self._max_dependencies]

        vulnerability_results = self._query_osv_for_dependencies(dependencies)
        findings: List[dict] = []
        for dep, vulnerabilities in vulnerability_results:
            if vulnerabilities:
                findings.append(self._normalize_finding(dep, vulnerabilities))
        return findings

    def _query_osv_for_dependencies(self, dependencies: List[DependencyEntry]) -> List[tuple[DependencyEntry, List[dict]]]:
        if not dependencies:
            return []

        now = time.time()
        if now < self._osv_circuit_open_until:
            results: List[tuple[DependencyEntry, List[dict]]] = []
            for dep in dependencies:
                cache_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
                cached = self._cache.get(cache_key)
                vulnerabilities = cached[1] if cached and now - cached[0] < self.ttl_seconds else []
                results.append((dep, vulnerabilities))
            return results

        unique_by_key: dict[str, DependencyEntry] = {}
        for dep in dependencies:
            key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
            if key not in unique_by_key:
                unique_by_key[key] = dep

        batched_entries = list(unique_by_key.values())
        unresolved: list[DependencyEntry] = []
        vuln_by_key: dict[str, List[dict]] = {}

        for dep in batched_entries:
            cache_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
            cached = self._cache.get(cache_key)
            if cached and now - cached[0] < self.ttl_seconds:
                vuln_by_key[cache_key] = cached[1]
            else:
                unresolved.append(dep)

        if unresolved:
            query_batch_payload = {
                "queries": [
                    {
                        "package": {
                            "name": dep.name,
                            "ecosystem": self._osv_ecosystem(dep.ecosystem),
                        },
                        "version": dep.version,
                    }
                    for dep in unresolved
                ]
            }

            batch_success = False
            batch_started_at = time.time()
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(self.OSV_BATCH_URL, json=query_batch_payload)
                latency = time.time() - batch_started_at
                if latency >= self._osv_circuit_latency_threshold:
                    self._osv_circuit_open_until = time.time() + float(self._osv_circuit_cooldown_seconds)

                if response.status_code == 200:
                    data = response.json() if response.content else {}
                    results = data.get("results") if isinstance(data, dict) else None
                    if isinstance(results, list) and len(results) == len(unresolved):
                        for dep, result_item in zip(unresolved, results):
                            cache_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
                            vulns = []
                            if isinstance(result_item, dict):
                                raw_vulns = result_item.get("vulns") or []
                                if isinstance(raw_vulns, list):
                                    vulns = [item for item in raw_vulns if isinstance(item, dict)]
                            self._cache[cache_key] = (time.time(), vulns)
                            vuln_by_key[cache_key] = vulns
                        batch_success = True
            except Exception:
                batch_success = False

            if not batch_success:
                # Batch-only mode for predictable runtime under load.
                self._osv_circuit_open_until = time.time() + float(self._osv_circuit_cooldown_seconds)
                for dep in unresolved:
                    cache_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
                    vuln_by_key[cache_key] = []
                    self._cache[cache_key] = (time.time(), [])

        results: List[tuple[DependencyEntry, List[dict]]] = []
        for dep in dependencies:
            key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
            results.append((dep, vuln_by_key.get(key, [])))
        return results

    def _collect_dependencies(self, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        for path in sorted(repo_dir.rglob("package.json")):
            entries.extend(self._parse_package_json(path, repo_dir))
        for path in sorted(repo_dir.rglob("package-lock.json")):
            entries.extend(self._parse_package_lock(path, repo_dir))
        for path in sorted(repo_dir.rglob("yarn.lock")):
            entries.extend(self._parse_yarn_lock(path, repo_dir))
        for path in sorted(repo_dir.rglob("pnpm-lock.yaml")):
            entries.extend(self._parse_pnpm_lock(path, repo_dir))
        for path in sorted(repo_dir.rglob("requirements.txt")):
            entries.extend(self._parse_requirements(path, repo_dir))
        for path in sorted(repo_dir.rglob("pyproject.toml")):
            entries.extend(self._parse_pyproject(path, repo_dir))
        for path in sorted(repo_dir.rglob("pom.xml")):
            entries.extend(self._parse_pom(path, repo_dir))
        for path in sorted(repo_dir.rglob("build.gradle")):
            entries.extend(self._parse_gradle(path, repo_dir))
        for path in sorted(repo_dir.rglob("build.gradle.kts")):
            entries.extend(self._parse_gradle(path, repo_dir))
        for path in sorted(repo_dir.rglob("go.mod")):
            entries.extend(self._parse_go_mod(path, repo_dir))
        for path in sorted(repo_dir.rglob("*.csproj")):
            entries.extend(self._parse_csproj(path, repo_dir))
        for path in sorted(repo_dir.rglob("packages.config")):
            entries.extend(self._parse_packages_config(path, repo_dir))

        deduped: List[DependencyEntry] = []
        seen: set[tuple[str, str, str, str]] = set()
        for dep in entries:
            key = (dep.ecosystem, dep.name.lower(), dep.version, dep.manifest_path)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(dep)
        return deduped

    @staticmethod
    def _rel(path: Path, root: Path) -> str:
        try:
            return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
        except Exception:
            return str(path).replace("\\", "/")

    def _parse_package_json(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []

        entries: List[DependencyEntry] = []
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, raw_version in deps.items():
                if not isinstance(name, str):
                    continue
                parsed = self._parse_npm_manifest_dependency(name, raw_version)
                if not parsed:
                    continue
                package_name, version = parsed
                entries.append(
                    DependencyEntry(
                        ecosystem="npm",
                        name=package_name,
                        version=version,
                        manifest_path=self._rel(path, repo_dir),
                    )
                )
        return entries

    def _parse_package_lock(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []

        entries: List[DependencyEntry] = []

        dependencies = data.get("dependencies") or {}
        if isinstance(dependencies, dict):
            for name, info in dependencies.items():
                if not isinstance(name, str) or not isinstance(info, dict):
                    continue
                version = self._normalize_version(str(info.get("version") or ""))
                package_name = self._normalize_npm_package_name(name)
                if not package_name or not version:
                    continue
                entries.append(
                    DependencyEntry(
                        ecosystem="npm",
                        name=package_name,
                        version=version,
                        manifest_path=self._rel(path, repo_dir),
                        line=1,
                    )
                )

        packages = data.get("packages") or {}
        if isinstance(packages, dict):
            for package_path, info in packages.items():
                if not isinstance(package_path, str) or not isinstance(info, dict):
                    continue
                if package_path.strip() == "":
                    # Root project metadata is not a dependency entry.
                    continue
                raw_name = str(info.get("name") or "").strip()
                name = raw_name or str(package_path).split("node_modules/")[-1].strip()
                name = self._normalize_npm_package_name(name)
                version = self._normalize_version(str(info.get("version") or ""))
                if not name or not version:
                    continue
                entries.append(
                    DependencyEntry(
                        ecosystem="npm",
                        name=name,
                        version=version,
                        manifest_path=self._rel(path, repo_dir),
                        line=1,
                    )
                )

        return entries

    def _parse_npm_manifest_dependency(self, name: str, raw_version: object) -> tuple[str, str] | None:
        package_name = self._normalize_npm_package_name(name)
        spec = str(raw_version or "").strip()
        if not package_name or not spec:
            return None

        if spec.startswith("npm:"):
            alias_target = spec[len("npm:") :].strip()
            alias_name, alias_version_spec = self._split_npm_alias_target(alias_target)
            if alias_name:
                package_name = alias_name
            spec = alias_version_spec

        if spec.startswith("workspace:"):
            spec = spec[len("workspace:") :].strip()
            if spec in {"", "*", "^", "~"}:
                return None

        non_registry_prefixes = ("file:", "link:", "git+", "github:", "http://", "https://")
        if spec.startswith(non_registry_prefixes):
            return None

        version = self._normalize_version(spec)
        if not version:
            return None
        return package_name, version

    @staticmethod
    def _split_npm_alias_target(alias_target: str) -> tuple[str, str]:
        value = str(alias_target or "").strip()
        if not value:
            return "", ""

        if value.startswith("@"):
            idx = value.rfind("@")
            if idx <= 0:
                return "", ""
            return value[:idx], value[idx + 1 :]

        idx = value.rfind("@")
        if idx <= 0:
            return "", ""
        return value[:idx], value[idx + 1 :]

    @staticmethod
    def _normalize_npm_package_name(name: str) -> str:
        value = str(name or "").strip()
        if not value:
            return ""
        if "node_modules/" in value:
            value = value.split("node_modules/")[-1].strip()
        return value

    def _parse_yarn_lock(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        entries: List[DependencyEntry] = []
        current_names: list[str] = []

        for line in lines:
            key_match = re.match(r'^("?[^"]+"?):\s*$', line)
            if key_match and not line.startswith(" "):
                raw_key = key_match.group(1).strip().strip('"')
                specs = [item.strip().strip('"') for item in raw_key.split(",") if item.strip()]
                names: list[str] = []
                for spec in specs:
                    name = self._name_from_npm_lock_spec(spec)
                    if name:
                        names.append(name)
                current_names = names
                continue

            version_match = re.match(r'^\s{2}version\s+"([^"]+)"\s*$', line)
            if version_match and current_names:
                version = self._normalize_version(version_match.group(1))
                if not version:
                    continue
                for name in current_names:
                    entries.append(
                        DependencyEntry(
                            ecosystem="npm",
                            name=name,
                            version=version,
                            manifest_path=self._rel(path, repo_dir),
                            line=1,
                        )
                    )
                current_names = []

        return entries

    def _parse_pnpm_lock(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        entries: List[DependencyEntry] = []
        in_packages = False

        for line in lines:
            stripped = line.strip()
            if stripped == "packages:":
                in_packages = True
                continue
            if not in_packages:
                continue
            if stripped and not line.startswith("  "):
                # next top-level section
                break

            match = re.match(r"^\s{2}(/[^:]+):\s*$", line)
            if not match:
                continue

            ident = match.group(1).lstrip("/")
            if "(" in ident:
                ident = ident.split("(", 1)[0]

            if "@" not in ident:
                continue

            name, raw_version = ident.rsplit("@", 1)
            version = self._normalize_version(raw_version)
            if not name or not version:
                continue

            entries.append(
                DependencyEntry(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=1,
                )
            )

        return entries

    def _parse_requirements(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return entries

        for line_number, line in enumerate(lines, start=1):
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            if stripped.startswith(("git+", "http://", "https://")):
                continue

            if ";" in stripped:
                stripped = stripped.split(";", 1)[0].strip()
            if not stripped:
                continue

            # Supports forms like: name==1.2.3, name[extra]>=1.0, name ~= 2.1
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)\s*([A-Za-z0-9_.-]+)", stripped)
            if not match:
                continue
            name, _op, raw_version = match.groups()
            if not name:
                continue
            version = self._normalize_version(raw_version or "")
            if not version:
                continue
            entries.append(
                DependencyEntry(
                    ecosystem="PyPI",
                    name=name,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=line_number,
                )
            )
        return entries

    def _parse_pyproject(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        if tomllib is None:
            return entries

        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return entries

        # PEP 621: [project] dependencies = ["pkg>=1.2"]
        project = data.get("project") or {}
        for dep_spec in project.get("dependencies") or []:
            if not isinstance(dep_spec, str):
                continue
            name, version = self._split_dep_spec(dep_spec)
            if not name or not version:
                continue
            entries.append(
                DependencyEntry(
                    ecosystem="PyPI",
                    name=name,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=1,
                )
            )

        # Poetry: [tool.poetry.dependencies]
        poetry = ((data.get("tool") or {}).get("poetry") or {})
        poetry_deps = poetry.get("dependencies") or {}
        if isinstance(poetry_deps, dict):
            for name, raw_version in poetry_deps.items():
                if str(name).strip().lower() == "python":
                    continue
                if isinstance(raw_version, str):
                    version = self._normalize_version(raw_version)
                elif isinstance(raw_version, dict):
                    version = self._normalize_version(str(raw_version.get("version") or ""))
                else:
                    version = ""

                if not str(name).strip() or not version:
                    continue
                entries.append(
                    DependencyEntry(
                        ecosystem="PyPI",
                        name=str(name).strip(),
                        version=version,
                        manifest_path=self._rel(path, repo_dir),
                        line=1,
                    )
                )

        return entries

    def _split_dep_spec(self, dep_spec: str) -> tuple[str, str]:
        cleaned = dep_spec.split(";", 1)[0].strip()
        if not cleaned:
            return "", ""

        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", cleaned)
        if not match:
            return "", ""

        name = str(match.group(1) or "").strip()
        constraints = str(match.group(2) or "").strip()
        version = self._normalize_version(constraints)
        return name, version

    def _parse_pom(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return entries

        # Ignore namespaces by checking local-name suffixes.
        for dep in root.iter():
            if not dep.tag.endswith("dependency"):
                continue
            group_id = self._child_text(dep, "groupId")
            artifact_id = self._child_text(dep, "artifactId")
            version = self._normalize_version(self._child_text(dep, "version"))
            if not group_id or not artifact_id or not version:
                continue
            entries.append(
                DependencyEntry(
                    ecosystem="Maven",
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                )
            )
        return entries

    def _parse_gradle(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return entries

        pattern = re.compile(
            r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*(?:\(|\s+)['\"]([^:'\"]+):([^:'\"]+):([^'\")]+)['\"]"
        )

        for line_number, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if not match:
                continue
            group_id, artifact_id, raw_version = match.groups()
            version = self._normalize_version(raw_version)
            if not group_id or not artifact_id or not version:
                continue
            entries.append(
                DependencyEntry(
                    ecosystem="Maven",
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=line_number,
                )
            )

        return entries

    def _parse_go_mod(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return entries

        in_require_block = False
        for line_number, line in enumerate(lines, start=1):
            stripped = line.split("//", 1)[0].strip()
            if not stripped:
                continue

            if stripped.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and stripped == ")":
                in_require_block = False
                continue

            match = None
            if in_require_block:
                match = re.match(r"^([^\s]+)\s+([^\s]+)$", stripped)
            else:
                match = re.match(r"^require\s+([^\s]+)\s+([^\s]+)$", stripped)

            if not match:
                continue

            name, raw_version = match.groups()
            version = self._normalize_version(raw_version)
            if not name or not version:
                continue

            entries.append(
                DependencyEntry(
                    ecosystem="Go",
                    name=name,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=line_number,
                )
            )

        return entries

    def _parse_csproj(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return entries

        for node in root.iter():
            if not node.tag.endswith("PackageReference"):
                continue

            include = str(node.attrib.get("Include") or node.attrib.get("Update") or "").strip()
            version_raw = str(node.attrib.get("Version") or "").strip()
            if not version_raw:
                version_raw = self._child_text(node, "Version")
            version = self._normalize_version(version_raw)
            if not include or not version:
                continue

            entries.append(
                DependencyEntry(
                    ecosystem="NuGet",
                    name=include,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=1,
                )
            )

        return entries

    def _parse_packages_config(self, path: Path, repo_dir: Path) -> List[DependencyEntry]:
        entries: List[DependencyEntry] = []
        try:
            root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return entries

        for node in root.iter():
            if not node.tag.endswith("package"):
                continue
            pkg_id = str(node.attrib.get("id") or "").strip()
            version = self._normalize_version(str(node.attrib.get("version") or "").strip())
            if not pkg_id or not version:
                continue

            entries.append(
                DependencyEntry(
                    ecosystem="NuGet",
                    name=pkg_id,
                    version=version,
                    manifest_path=self._rel(path, repo_dir),
                    line=1,
                )
            )

        return entries

    @staticmethod
    def _name_from_npm_lock_spec(spec: str) -> str:
        value = str(spec or "").strip()
        if not value:
            return ""
        # Handles scoped and unscoped specs, e.g. "@types/node@^20" or "lodash@^4".
        if value.startswith("@"):
            idx = value.rfind("@")
            if idx > 1:
                return value[:idx]
            return ""
        idx = value.rfind("@")
        if idx <= 0:
            return ""
        return value[:idx]

    @staticmethod
    def _child_text(node: ET.Element, child_name: str) -> str:
        for child in list(node):
            if child.tag.endswith(child_name):
                return (child.text or "").strip()
        return ""

    @staticmethod
    def _normalize_version(raw: str) -> str:
        if not raw:
            return ""
        value = raw.strip()
        value = re.sub(r"^[\^~<>=\s]+", "", value)
        value = re.sub(r"[^0-9A-Za-z._-].*$", "", value)
        if not any(ch.isdigit() for ch in value):
            return ""
        return value

    def _query_osv(self, dep: DependencyEntry) -> List[dict]:
        cache_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
        cached = self._cache.get(cache_key)
        now = time.time()
        if cached and now - cached[0] < self.ttl_seconds:
            return cached[1]

        payload = {
            "package": {
                "name": dep.name,
                "ecosystem": self._osv_ecosystem(dep.ecosystem),
            },
            "version": dep.version,
        }
        vulnerabilities: List[dict] = []
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(self.OSV_URL, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulns") or []
                    if isinstance(vulns, list):
                        vulnerabilities = [v for v in vulns if isinstance(v, dict)]
        except Exception:
            vulnerabilities = []

        self._cache[cache_key] = (now, vulnerabilities)
        return vulnerabilities

    @staticmethod
    def _osv_ecosystem(ecosystem: str) -> str:
        normalized = str(ecosystem or "").strip().lower()
        if normalized in {"npm", "pypi", "maven", "go", "nuget"}:
            return {
                "npm": "npm",
                "pypi": "PyPI",
                "maven": "Maven",
                "go": "Go",
                "nuget": "NuGet",
            }[normalized]
        return str(ecosystem or "").strip() or "npm"

    @staticmethod
    def _first_alias(vuln: dict) -> str:
        aliases = vuln.get("aliases") or []
        if isinstance(aliases, list) and aliases:
            return str(aliases[0])
        return str(vuln.get("id") or "OSV-UNKNOWN")

    @staticmethod
    def _severity(vuln: dict) -> str:
        database_specific = vuln.get("database_specific") or {}
        severity_raw = str(database_specific.get("severity") or "").upper()
        if severity_raw in {"CRITICAL", "HIGH"}:
            return "HIGH"
        if severity_raw in {"MEDIUM", "MODERATE"}:
            return "MEDIUM"
        if severity_raw in {"LOW"}:
            return "LOW"

        # OSV may provide CVSS vectors/scores under `severity`.
        score = DependencyScanner._cvss_score(vuln)
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "MEDIUM"

    @staticmethod
    def _cvss_score(vuln: dict) -> float:
        severities = vuln.get("severity") or []
        if not isinstance(severities, list):
            return 0.0

        best = 0.0
        for item in severities:
            if not isinstance(item, dict):
                continue
            score_raw = str(item.get("score") or "")
            # Handles either a numeric score or CVSS vector ending with /.../S:C/ C:H/I:H/A:H + base score.
            number = re.search(r"(\d+(?:\.\d+)?)", score_raw)
            if not number:
                continue
            try:
                parsed = float(number.group(1))
            except ValueError:
                continue
            best = max(best, parsed)
        return best

    @staticmethod
    def _severity_rank(severity: str) -> int:
        normalized = str(severity or "MEDIUM").upper()
        if normalized == "HIGH":
            return 3
        if normalized == "MEDIUM":
            return 2
        if normalized == "LOW":
            return 1
        return 0

    @staticmethod
    def _is_prerelease(version: str) -> bool:
        value = str(version or "").strip().lower()
        if not value:
            return False
        if "-" in value and any(tag in value for tag in ["alpha", "beta", "rc", "pre", "next", "snapshot"]):
            return True
        return False

    @staticmethod
    def _version_sort_key(version: str) -> tuple:
        value = str(version or "").strip().lstrip("vV")
        core = re.split(r"[+-]", value, maxsplit=1)[0]
        parts: list[tuple[int, object]] = []
        for token in re.split(r"[._]", core):
            if token.isdigit():
                parts.append((0, int(token)))
                continue
            match = re.match(r"^(\d+)([A-Za-z].*)$", token)
            if match:
                parts.append((0, int(match.group(1))))
                parts.append((1, match.group(2).lower()))
            elif token:
                parts.append((1, token.lower()))
        return tuple(parts)

    def _is_version_greater(self, candidate: str, current: str) -> bool:
        return self._version_sort_key(candidate) > self._version_sort_key(current)

    def _best_fixed_version(self, vulnerabilities: List[dict], current_version: str) -> Optional[str]:
        candidates: list[str] = []
        for vuln in vulnerabilities:
            fixed = self._fixed_version(vuln, current_version)
            if fixed:
                candidates.append(str(fixed))

        if not candidates:
            return None

        deduped = list(dict.fromkeys(candidates))
        stable = [version for version in deduped if not self._is_prerelease(version)]
        pool = stable or deduped

        current = str(current_version or "").strip()
        if current:
            higher = [version for version in pool if self._is_version_greater(version, current)]
            if higher:
                pool = higher

        return min(pool, key=self._version_sort_key)

    def _fixed_version(self, vuln: dict, current_version: str) -> Optional[str]:
        fixed_versions: list[str] = []
        for affected in vuln.get("affected") or []:
            for rng in affected.get("ranges") or []:
                events = rng.get("events") or []
                for event in events:
                    fixed = str(event.get("fixed") or "").strip()
                    if fixed:
                        fixed_versions.append(fixed)

        if not fixed_versions:
            return None

        # Keep order deterministic while removing duplicates.
        deduped = list(dict.fromkeys(fixed_versions))
        stable = [version for version in deduped if not self._is_prerelease(version)]
        pool = stable or deduped

        current = str(current_version or "").strip()
        if current:
            higher = [version for version in pool if self._is_version_greater(version, current)]
            if higher:
                pool = higher

        # Prefer the smallest safe bump to reduce breakage risk.
        return min(pool, key=self._version_sort_key)

    def _normalize_finding(self, dep: DependencyEntry, vulnerabilities: List[dict]) -> dict:
        if not vulnerabilities:
            raise ValueError("vulnerabilities must be non-empty")

        representative = sorted(
            vulnerabilities,
            key=lambda vuln: self._severity_rank(self._severity(vuln)),
            reverse=True,
        )[0]

        severity = self._severity(representative)
        cves = [self._first_alias(vuln) for vuln in vulnerabilities]
        unique_cves = list(dict.fromkeys(cves))
        cve = unique_cves[0]

        if len(unique_cves) == 1:
            summary = str(representative.get("summary") or "Known vulnerable dependency detected")
        else:
            summary = f"{dep.name}@{dep.version} has {len(unique_cves)} known vulnerabilities (e.g., {cve})."

        impact_description = " ".join(
            [
                summary,
                str(representative.get("details") or ""),
                " ".join(unique_cves),
            ]
        ).strip()
        impact_category = self._classify_impact(impact_description)
        impact_label = self.IMPACT_LABELS.get(impact_category, "Unknown")

        fix_version = self._best_fixed_version(vulnerabilities, dep.version)
        if not fix_version:
            ecosystem_lower = str(dep.ecosystem or "").lower()
            fix_version = KNOWN_FIX_VERSIONS.get(ecosystem_lower, {}).get(str(dep.name or "").lower())
        fix_text = f"Upgrade to {fix_version}" if fix_version else "Upgrade to a patched version"
        exploitability = self._exploitability_profile(vulnerabilities)
        return {
            "type": "dependency_vuln",
            "severity": severity,
            "package": dep.name,
            "version": dep.version,
            "manifest_path": dep.manifest_path,
            "line": max(1, int(dep.line or 1)),
            "cve": cve,
            "issue": summary,
            "fix": fix_text,
            "fix_version": fix_version,
            "confidence": 100,
            "confidence_label": "HIGH",
            "ecosystem": dep.ecosystem,
            "public_exploit": exploitability["public_exploit"],
            "network_access": exploitability["network_access"],
            "auth_required": exploitability["auth_required"],
            "low_complexity": exploitability["low_complexity"],
            "exploitability_score": exploitability["score"],
            "exploitability_level": exploitability["level"],
            "exploitability_reasons": exploitability["reasons"],
            "impact_category": impact_category,
            "impact_label": impact_label,
        }

    @staticmethod
    def _classify_impact(description: str) -> str:
        desc = str(description or "").lower()
        if "remote code execution" in desc or "rce" in desc:
            return "RCE"
        if "denial of service" in desc or "dos" in desc:
            return "DoS"
        if "exposure" in desc or "leak" in desc:
            return "Data Leak"
        if "bypass" in desc:
            return "Auth Bypass"
        if "injection" in desc:
            return "Injection"
        return "Unknown"

    @staticmethod
    def _cvss_vector(vuln: dict) -> str:
        severities = vuln.get("severity") or []
        if not isinstance(severities, list):
            return ""
        for item in severities:
            if not isinstance(item, dict):
                continue
            score_raw = str(item.get("score") or "").strip()
            if "AV:" in score_raw or "CVSS:" in score_raw:
                return score_raw
        return ""

    @staticmethod
    def _reference_urls(vuln: dict) -> list[str]:
        refs = vuln.get("references") or []
        urls: list[str] = []
        if not isinstance(refs, list):
            return urls
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            url = str(ref.get("url") or "").strip()
            if url:
                urls.append(url.lower())
        return urls

    @staticmethod
    def _reference_types(vuln: dict) -> list[str]:
        refs = vuln.get("references") or []
        ref_types: list[str] = []
        if not isinstance(refs, list):
            return ref_types
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            rtype = str(ref.get("type") or "").strip().upper()
            if rtype:
                ref_types.append(rtype)
        return ref_types

    @classmethod
    def _signal_public_exploit(cls, vuln: dict) -> bool:
        ref_types = set(cls._reference_types(vuln))
        if any(kind in ref_types for kind in {"EXPLOIT", "POC"}):
            return True

        urls = cls._reference_urls(vuln)
        exploit_markers = (
            "exploit-db",
            "packetstormsecurity",
            "metasploit",
            "github.com",
            "/poc",
            "proof-of-concept",
            "exploit",
        )
        return any(any(marker in url for marker in exploit_markers) for url in urls)

    @classmethod
    def _signal_network_access(cls, vuln: dict) -> bool:
        vector = cls._cvss_vector(vuln).upper()
        if "AV:N" in vector:
            return True
        database_specific = vuln.get("database_specific") or {}
        av = str(database_specific.get("attackVector") or database_specific.get("attack_vector") or "").upper()
        return av in {"NETWORK", "N"}

    @classmethod
    def _signal_auth_required(cls, vuln: dict) -> bool:
        vector = cls._cvss_vector(vuln).upper()
        if "PR:N" in vector:
            return False
        if "PR:L" in vector or "PR:H" in vector:
            return True

        database_specific = vuln.get("database_specific") or {}
        pr = str(database_specific.get("privilegesRequired") or database_specific.get("privileges_required") or "").upper()
        if pr in {"NONE", "N"}:
            return False
        if pr in {"LOW", "HIGH", "L", "H"}:
            return True
        return True

    @classmethod
    def _signal_low_complexity(cls, vuln: dict) -> bool:
        vector = cls._cvss_vector(vuln).upper()
        if "AC:L" in vector:
            return True

        database_specific = vuln.get("database_specific") or {}
        ac = str(database_specific.get("attackComplexity") or database_specific.get("attack_complexity") or "").upper()
        return ac in {"LOW", "L"}

    @classmethod
    def _exploitability_profile(cls, vulnerabilities: List[dict]) -> dict:
        public_exploit = any(cls._signal_public_exploit(vuln) for vuln in vulnerabilities)
        network_access = any(cls._signal_network_access(vuln) for vuln in vulnerabilities)
        auth_required = all(cls._signal_auth_required(vuln) for vuln in vulnerabilities)
        low_complexity = any(cls._signal_low_complexity(vuln) for vuln in vulnerabilities)

        score = 0
        reasons: list[str] = []
        if public_exploit:
            score += 3
            reasons.append("Public exploit available")
        if network_access:
            score += 2
            reasons.append("Network accessible")
        if not auth_required:
            score += 2
            reasons.append("No authentication required")
        if low_complexity:
            score += 2
            reasons.append("Low attack complexity")

        if score >= 6:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "public_exploit": public_exploit,
            "network_access": network_access,
            "auth_required": auth_required,
            "low_complexity": low_complexity,
            "score": score,
            "level": level,
            "reasons": reasons,
        }
