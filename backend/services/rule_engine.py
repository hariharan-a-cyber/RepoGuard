import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from backend.utils.security import is_excluded_path


@dataclass(frozen=True)
class RuleMatch:
    name: str
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: int
    snippet: str


@dataclass(frozen=True)
class RuleResult:
    matches: List[RuleMatch]
    files_scanned: int
    patterns_checked: int


@dataclass(frozen=True)
class RuleDefinition:
    name: str
    rule_id: str
    pattern: re.Pattern[str]
    severity: str
    message: str


class RuleEngine:
    """High-signal deterministic detector for core vulnerability classes."""

    SOURCE_EXTENSIONS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".ini",
        ".cfg",
        ".conf",
    }

    MAX_FILE_BYTES = 300_000

    def __init__(self) -> None:
        self.rules: list[RuleDefinition] = [
            RuleDefinition(
                name="Hardcoded Secret",
                rule_id="regex.hardcoded-secret",
                pattern=re.compile(
                    r"(?:api[_-]?key|secret[_-]?key|secret|token|password|passwd|jwt[_-]?secret|auth[_-]?token|access[_-]?key)"
                    r"\s*(?:=|:)\s*[\"']([^\"']{16,})[\"']",
                    re.IGNORECASE,
                ),
                severity="HIGH",
                message="Hardcoded secret detected in source code.",
            ),
            RuleDefinition(
                name="Command Execution API",
                rule_id="regex.command-injection",
                pattern=re.compile(
                    r"(os\.system|os\.popen|subprocess\.(run|Popen|call)\(|Runtime\.getRuntime\(\)\.exec"
                    r"|(?<!\w)exec\s*\(|execSync\s*\(|execFile\s*\(|spawn\s*\(|spawnSync\s*\()",
                    re.IGNORECASE,
                ),
                severity="HIGH",
                message="Potential command injection vector detected.",
            ),
            RuleDefinition(
                name="SQL Injection",
                rule_id="regex.sql-injection",
                pattern=re.compile(r"(SELECT|INSERT|UPDATE|DELETE)[^\n;]*(\+|`|\$\{)", re.IGNORECASE),
                severity="HIGH",
                message="SQL query appears to be built via string interpolation/concatenation.",
            ),
            RuleDefinition(
                name="Insecure Auth Logic",
                rule_id="regex.insecure-auth",
                pattern=re.compile(
                    r"(if\s*\(?\s*password\s*==\s*['\"]"
                    r"|auth\s*=\s*false"
                    r"|verify\s*=\s*false"
                    r"|password\s*===?\s*['\"][^'\"]{1,30}['\"])",
                    re.IGNORECASE,
                ),
                severity="MEDIUM",
                message="Insecure authentication logic detected.",
            ),
            RuleDefinition(
                name="Open Redirect",
                rule_id="regex.open-redirect",
                pattern=re.compile(r"(redirect\(|res\.redirect\(|window\.location\s*=).*(req\.|request\.|query|params|next)", re.IGNORECASE),
                severity="MEDIUM",
                message="Open redirect pattern detected from user-controlled destination.",
            ),
            RuleDefinition(
                name="Unsafe YAML Load",
                rule_id="regex.unsafe-yaml-load",
                pattern=re.compile(r"yaml\.load\s*\(", re.IGNORECASE),
                severity="HIGH",
                message="Unsafe YAML deserialization pattern detected.",
            ),
            RuleDefinition(
                name="Unsafe Pickle Load",
                rule_id="regex.unsafe-pickle-load",
                pattern=re.compile(r"pickle\.loads?\s*\(", re.IGNORECASE),
                severity="HIGH",
                message="Unsafe pickle deserialization pattern detected.",
            ),
            RuleDefinition(
                name="Insecure CORS Configuration",
                rule_id="regex.insecure-cors",
                pattern=re.compile(r"\bcors\s*\(", re.IGNORECASE),
                severity="MEDIUM",
                message="Potentially permissive CORS configuration detected.",
            ),
            RuleDefinition(
                name="Credential in URL",
                rule_id="regex.credential-url",
                pattern=re.compile(r"https?://[^\s\"']+:[^@\s\"']+@", re.IGNORECASE),
                severity="HIGH",
                message="Credentials embedded in URL detected.",
            ),
            RuleDefinition(
                name="Weak Random Generator Usage",
                rule_id="regex.weak-random",
                pattern=re.compile(
                    r"Math\.random\(\)|random\.randint|random\.random\(\)|random\.choice\b|rand\(\)|mt_rand\(",
                    re.IGNORECASE,
                ),
                severity="LOW",
                message="Weak random number generator used. Use a cryptographically secure alternative.",
            ),
            RuleDefinition(
                name="Server-Side Template Injection",
                rule_id="regex.ssti",
                pattern=re.compile(
                    r"render_template_string\s*\(.*(?:f['\"]|request\.|%|\+)",
                    re.IGNORECASE,
                ),
                severity="HIGH",
                message="render_template_string with user input enables Server-Side Template Injection (SSTI).",
            ),
            RuleDefinition(
                name="JWT Without Expiry",
                rule_id="regex.jwt-no-expiry",
                pattern=re.compile(
                    r"jwt\.sign\s*\([^)]*\)",
                    re.IGNORECASE,
                ),
                severity="MEDIUM",
                message="JWT token created - verify expiresIn is set to prevent tokens from being valid forever.",
            ),
            RuleDefinition(
                name="Path Traversal",
                rule_id="regex.path-traversal",
                pattern=re.compile(
                    r"(?:send_file|sendFile|open|readFile|readFileSync|createReadStream)\s*\([^)]*"
                    r"(?:\+|`|\$\{|os\.path\.join|path\.join)",
                    re.IGNORECASE,
                ),
                severity="HIGH",
                message="File path appears to incorporate user input - possible path traversal.",
            ),
            RuleDefinition(
                name="NoSQL Injection",
                rule_id="regex.nosql-injection",
                pattern=re.compile(
                    r"\.(?:find|findone|update|updateone|deleteone|delete|aggregate)\s*\(\s*\{[^}]*"
                    r"(?:req\.(?:body|query|params)|request\.)",
                    re.IGNORECASE,
                ),
                severity="HIGH",
                message="User input passed directly into a NoSQL query object - possible NoSQL injection.",
            ),
        ]

    def load_external_rules(self, rules_dir: str = "backend/rules") -> None:
        """Load additional rules from JSON files in the rules directory."""
        rules_path = Path(os.fspath(rules_dir))
        if not rules_path.exists():
            return

        for json_file in rules_path.rglob("*.json"):
            try:
                with open(json_file, encoding="utf-8") as f:
                    data = json.load(f)
                # Convert to internal RuleDefinition format
                self.rules.append(RuleDefinition(
                    name=data["name"],
                    rule_id=data["id"],
                    pattern=re.compile(data["pattern"], re.IGNORECASE),
                    severity=data["severity"].upper(),
                    message=data["description"],
                ))
            except Exception as e:
                print(f"Warning: Could not load rule {json_file}: {e}")

    @staticmethod
    def _is_test_file(path: str) -> bool:
        normalized = (path or "").lower()
        return any(token in normalized for token in ["/test", "tests/", "spec.", "_test."])

    @staticmethod
    def _valid_secret(snippet: str) -> bool:
        secret_match = re.search(r"[\"']([^\"']+)[\"']", snippet)
        if not secret_match:
            return False
        secret_val = secret_match.group(1).strip()
        placeholders = {
            "test",
            "example",
            "changeme",
            "dummy",
            "sample",
            "placeholder",
            "your_key_here",
            "insert_here",
            "replace_me",
            "xxx",
            "abc123",
            "fake",
            "mock",
            "redacted",
        }
        lowered_val = secret_val.lower()
        if lowered_val in placeholders:
            return False
        # Suppress obvious non-secrets whose value embeds a placeholder marker,
        # e.g. "test_password_placeholder_value" or "fake-api-key-sample".
        if any(token in lowered_val for token in ("placeholder", "changeme", "your_key_here", "replace_me", "insert_here", "redacted", "example")):
            return False
        return len(secret_val) >= 12

    @staticmethod
    def _is_valid_match(rule_id: str, snippet: str, file_path: str) -> bool:
        if RuleEngine._is_test_file(file_path):
            return False
        # Python files: these categories are handled by the stdlib AST analyzer
        # (analyze_python_ast) which only fires on real call expressions, never on
        # string literals or comments.  Suppress the regex rules to avoid FPs.
        if file_path.endswith(".py") and rule_id in {
            "regex.unsafe-pickle-load", "regex.unsafe-yaml-load",
            "regex.command-injection", "regex.weak-random",
        }:
            return False
        lowered_snip = snippet.lower()
        # Global guard: keywords appearing inside log/print statements are not
        # executable queries/commands - suppress these low-signal matches.
        is_log_line = any(
            token in lowered_snip
            for token in ["logging.", "logger.", "log.info", "log.debug", "log.warn", "log.error", "print(", "console.log"]
        )
        sql_like_rule = "sql" in rule_id.lower()
        if is_log_line and sql_like_rule:
            return False
        if rule_id == "regex.hardcoded-secret":
            return RuleEngine._valid_secret(snippet)
        if rule_id == "regex.sql-injection":
            lowered = snippet.lower()
            # Suppress when SQL keyword appears inside a log/print/comment string
            # rather than an actual query execution.
            if any(token in lowered for token in ["logging.", "logger.", "log.info", "log.debug", "print(", "console.log", "# ", "-style", "example"]):
                return False
            return any(token in lowered for token in ["request", "input", "user", "query", "params", "+"])
        if rule_id == "regex.path-traversal":
            lowered = snippet.lower()
            return any(token in lowered for token in ["request", "req.", "input", "args", "params", "query", "+", "join"])
        if rule_id == "regex.nosql-injection":
            return True
        if rule_id == "regex.command-injection":
            s = snippet.lower()
            if s.strip().startswith(("import ", "from ")):
                return False
            return any(
                token in s
                for token in ["request", "input", "args", "shell=true", "+", "os.system(", "exec("]
            )
        if rule_id == "regex.jwt-no-expiry":
            return "expiresin" not in snippet.lower()
        if rule_id == "regex.open-redirect":
            lowered = snippet.lower()
            if not any(token in lowered for token in ["next", "returnurl", "redirect", "req.", "request.", "query"]):
                return False
            # Suppress when the user value is used as a lookup key into an
            # allowlist object/array (e.g. ALLOWED[req.query.dest]) or via a
            # lookup method (ROUTES.get(req.query.to)) rather than passed
            # directly as the redirect target.
            if re.search(r"\[\s*(req|request)\.[^\]]+\]", snippet, re.IGNORECASE):
                return False
            if re.search(r"\.(?:get|has|includes|find|indexof)\s*\(\s*(req|request)\.", snippet, re.IGNORECASE):
                return False
            return True
        if rule_id == "regex.weak-random":
            fname = (file_path or "").lower()
            if any(t in fname for t in ("generate", "dataset", "seed", "mock", "fixture", "sample", "factory", "/data/", "/test")):
                return False
            # Weak RNG matters in security contexts. Only suppress when the line
            # clearly indicates cosmetic use (UI, color, animation, jitter).
            lowered = snippet.lower()
            cosmetic_tokens = [
                "color", "colour", "confetti", "animation", "animate",
                "particle", "shuffle", "jitter", "delay", "css", "style",
                "pixel", "rgb", "hsl", "emoji", "sample text",
                "backoff", "retry", "sleep", "timeout", "fuzz",
            ]
            return not any(token in lowered for token in cosmetic_tokens)
        if rule_id in {"regex.unsafe-yaml-load", "regex.unsafe-pickle-load"}:
            lowered = snippet.lower()
            return any(token in lowered for token in ["request", "input", "payload", "body", "file", "yaml.load", "pickle.load", "pickle.loads"])
        if rule_id == "regex.eval-usage":
            return any(token in snippet.lower() for token in ["request", "input", "user", "payload", "eval", "exec"])
        if rule_id == "regex.credential-url":
            return "@" in snippet and "://" in snippet
        return True

    def _iter_source_files(self, repo_dir: Path) -> Iterable[Path]:
        for path in repo_dir.rglob("*"):
            if not path.is_file():
                continue
            if is_excluded_path(path, repo_dir):
                continue
            if path.suffix.lower() not in self.SOURCE_EXTENSIONS:
                continue
            if path.stat().st_size > self.MAX_FILE_BYTES:
                continue
            yield path

    def scan_repository(self, repo_dir: Path) -> RuleResult:
        matches: list[RuleMatch] = []
        files_scanned = 0
        patterns_checked = 0

        for file_path in self._iter_source_files(repo_dir):
            files_scanned += 1
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            patterns_checked += len(self.rules)
            for rule in self.rules:
                for found in rule.pattern.finditer(text):
                    line = text[: found.start()].count("\n") + 1
                    snippet = text.splitlines()[max(0, line - 1)].strip() if text.splitlines() else ""
                    rel = str(file_path.relative_to(repo_dir)).replace("\\", "/")
                    if not self._is_valid_match(rule.rule_id, snippet, rel):
                        continue
                    matches.append(
                        RuleMatch(
                            name=rule.name,
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=rel,
                            line=line,
                            snippet=snippet,
                        )
                    )

        return RuleResult(matches=matches, files_scanned=files_scanned, patterns_checked=patterns_checked)
