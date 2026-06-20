from typing import Dict

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_PENALTIES: Dict[str, int] = {
    SEVERITY_CRITICAL: 20,
    SEVERITY_HIGH: 10,
    SEVERITY_MEDIUM: 5,
    SEVERITY_LOW: 2,
    SEVERITY_INFO: 1,
}


def normalize_semgrep_severity(raw: str) -> str:
    value = (raw or "").strip().upper()
    if value in {"ERROR", "HIGH"}:
        return SEVERITY_HIGH
    if value in {"WARNING", "MEDIUM"}:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def normalize_bandit_severity(raw: str) -> str:
    value = (raw or "").strip().upper()
    if value == SEVERITY_HIGH:
        return SEVERITY_HIGH
    if value == SEVERITY_MEDIUM:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def compute_risk_score(issues_count_by_severity: Dict[str, int]) -> int:
    score = 100
    for severity, count in issues_count_by_severity.items():
        penalty = SEVERITY_PENALTIES.get(severity, SEVERITY_PENALTIES[SEVERITY_LOW])
        score -= penalty * max(0, count)
    return max(0, min(100, score))


# Directories that contain third-party, generated, or vendored code that should
# never be scanned as the user's own source. Findings inside these are noise:
# the user did not write them and cannot fix them. Dependency vulnerabilities in
# these packages are surfaced separately by the OSV dependency scanner.
EXCLUDED_SCAN_DIRS = frozenset({
    "node_modules", "bower_components", "jspm_packages",
    "vendor", "vendors", "third_party", "third-party",
    "dist", "build", "out", "target", "bin", "obj",
    ".venv", "venv", "env", "virtualenv", "site-packages",
    "__pycache__", ".git", ".svn", ".hg", ".tox", ".mypy_cache",
    ".pytest_cache", ".next", ".nuxt", ".cache", "coverage",
    ".gradle", ".idea", ".vscode",
})


def is_excluded_path(path, repo_dir) -> bool:
    """Return True if a file path lives inside a vendored/generated directory
    (e.g. node_modules, .venv, dist) and should be skipped by source scanners."""
    try:
        rel_parts = [p.lower() for p in path.relative_to(repo_dir).parts]
    except (ValueError, AttributeError):
        rel_parts = [p.lower() for p in getattr(path, "parts", ())]
    if any(part in EXCLUDED_SCAN_DIRS for part in rel_parts):
        return True
    # Skip minified bundles regardless of directory.
    name = str(getattr(path, "name", "")).lower()
    if name.endswith((".min.js", ".min.css", ".bundle.js", ".chunk.js")):
        return True
    return False
