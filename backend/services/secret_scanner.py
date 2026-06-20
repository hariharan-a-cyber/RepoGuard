import re
from pathlib import Path
from typing import List

from backend.utils.security import is_excluded_path

# These patterns match common accidentally-committed secrets
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]"
        ),
        "severity": "critical",
    },
    {
        "name": "Generic Secret or Password",
        "pattern": re.compile(
            r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ),
        "severity": "high",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "high",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"gh[ps]_[A-Za-z0-9]{36}"),
        "severity": "critical",
    },
    {
        "name": "Stripe Live Key",
        "pattern": re.compile(r"(?:sk|rk|pk)_live_[A-Za-z0-9]{20,}"),
        "severity": "critical",
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "severity": "critical",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "severity": "critical",
    },
    {
        "name": "Private Key Block",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "severity": "critical",
    },
]

# File types to scan (skip images, binaries, etc.)
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".yaml", ".yml", ".json",
    ".rb", ".php", ".go", ".java",
    ".sh", ".bash", ".conf", ".ini", ".cfg",
}

MAX_FILE_BYTES = 200_000  # Skip files larger than 200KB

PLACEHOLDER_VALUES = {
    "correcthash", "password", "testpassword", "test_password", "yourpassword",
    "mypassword", "password123", "changeme", "secret", "mysecret", "test_secret",
    "example", "placeholder", "dummypassword", "fakepassword", "notapassword",
    "hashedpassword", "encryptedpassword", "testtoken", "faketoken",
}


def scan_secrets(repo_dir: Path) -> List[dict]:
    """Scan all source files for accidentally committed secrets."""
    findings = []
    # Directories that should not contribute production secret findings.
    non_prod_dirs = {
        "test", "tests", "spec", "specs", "__tests__",
        "fixtures", "mocks", "stubs", "examples", "demo",
    }
    for file_path in repo_dir.rglob("*"):
        if not file_path.is_file():
            continue

        if is_excluded_path(file_path, repo_dir):
            continue

        # Skip files in test/mocks/fixtures-style directories.
        relative_parts = {part.lower() for part in file_path.relative_to(repo_dir).parts[:-1]}
        if relative_parts & non_prod_dirs:
            continue

        # Skip obvious test filenames regardless of directory placement.
        fname = file_path.name.lower()
        if any(
            fname.endswith(suffix)
            for suffix in [".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.py", "test_.py"]
        ):
            continue

        if file_path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if file_path.stat().st_size > MAX_FILE_BYTES:
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            for rule in SECRET_PATTERNS:
                match = rule["pattern"].search(line)
                if not match:
                    continue

                groups = match.groups()
                secret_value = groups[-1].strip() if groups else ""
                if secret_value:
                    lowered_secret = secret_value.lower()
                    if lowered_secret in PLACEHOLDER_VALUES:
                        continue
                    # Suppress values that embed an obvious placeholder marker,
                    # e.g. "test_password_placeholder_value" or "fake-token-sample".
                    if any(
                        marker in lowered_secret
                        for marker in ("placeholder", "changeme", "example", "redacted", "your_", "_here", "replace_me", "dummy", "notreal", "fake", "sample")
                    ):
                        continue
                    if len(secret_value) < 12:
                        continue

                findings.append({
                    "type": "secret",
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": str(file_path.relative_to(repo_dir)),
                    "line": line_num,
                    "snippet": line.strip()[:120],  # Never log full secrets
                    "fix": "Move this value to an environment variable. "
                           "Rotate/revoke this credential immediately.",
                })
    return findings
