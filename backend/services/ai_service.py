import asyncio
import difflib
import json
import os
import re
import time
import warnings
from typing import List

import httpx
from dotenv import load_dotenv

from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.services.fix_templates import get_deterministic_fix

load_dotenv()

FIX_PROMPT_TEMPLATE = """
You are a security engineer. You have found this vulnerability:

Vulnerability type: {vuln_type}
File: {file_path}
Line: {line_number}

Vulnerable code:
{vulnerable_code}

Your task: Return ONLY the fixed version of the code above.
Do NOT add explanations.
Do NOT add comments.
Do NOT return markdown.
Return ONLY the corrected code that can be directly used as a replacement.
"""


class AIService:
    TEMPLATE_LOCKED_CATEGORIES = {
        "Unescaped HTML in Template (Potential XSS)",
        "Flask Debug Mode Enabled",
        "Unsafe YAML Deserialization",
        "Unsafe Pickle Deserialization",
        "Hardcoded Secrets",
        "Command Injection",
        "SQL Injection",
        "Dynamic Code Execution (eval/exec)",
        "Insecure CORS Configuration",
        "Credential in URL",
    }

    _GENERIC_MARKERS = [
        "secure coding patterns recommended by the scanner rule",
        "apply secure coding practices",
        "review the scanner message",
        "refactor this code path",
        "security issue detected",
        "no explanation returned",
        "no fix returned",
        "details unavailable",
        "safe api usage pattern",
        "review ai guidance",
    ]

    def __init__(self) -> None:
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash").strip() or "gemini-1.5-flash"
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.timeout_seconds = int(os.getenv("LLM_TIMEOUT_SECONDS", "45"))
        self.min_request_interval = float(os.getenv("LLM_MIN_REQUEST_INTERVAL", "0.25"))

        self._last_request_at = 0.0
        self._cache: dict[str, AIGuidance] = {}
        self._gemini_sdk = None
        self._gemini_import_error: str | None = None

        self.use_gemini = bool(self.gemini_api_key)
        self.gemini_model_candidates = [
            self.gemini_model,
            "gemini-1.5-flash-latest",
            "gemini-1.5-flash-001",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
        ]
        # Preserve order but remove duplicates.
        seen: set[str] = set()
        self.gemini_model_candidates = [
            name for name in self.gemini_model_candidates if not (name in seen or seen.add(name))
        ]

        if self.use_gemini:
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\.generativeai")
                    import google.generativeai as gemini_sdk  # type: ignore[import-not-found]

                self._gemini_sdk = gemini_sdk
                self._gemini_sdk.configure(api_key=self.gemini_api_key)
                self._gemini_client = self._gemini_sdk.GenerativeModel(self.gemini_model)
            except Exception as exc:
                self.use_gemini = False
                self._gemini_import_error = str(exc)
                self._gemini_client = None
        else:
            self._gemini_client = None

    def enabled(self) -> bool:
        return bool(self.use_gemini or self.api_key)

    @classmethod
    def is_template_locked_category(cls, category: str) -> bool:
        return (category or "").strip() in cls.TEMPLATE_LOCKED_CATEGORIES

    def _cache_key(self, issue: SecurityIssue) -> str:
        return "|".join(
            [
                issue.rule_id,
                issue.title,
                issue.severity,
                issue.category,
                issue.data_source,
                issue.usage_context,
                issue.file,
                str(issue.line),
                issue.message,
            ]
        )

    @staticmethod
    def _vuln_type(issue: SecurityIssue) -> str:
        text = f"{issue.category} {issue.rule_id} {issue.title}".lower()
        if "sql" in text:
            return "sql_injection"
        if "secret" in text or "credential" in text:
            return "hardcoded_secret"
        if "eval" in text or "exec" in text:
            return "dangerous_eval"
        return "generic"

    @staticmethod
    def _language_family(issue: SecurityIssue) -> str:
        path = (issue.file or "").lower()
        if path.endswith((".js", ".jsx", ".ts", ".tsx")):
            return "node"
        if path.endswith(".py"):
            return "python"
        return "all"

    @staticmethod
    def _sanitize_fix_code_output(content: str) -> str:
        text = (content or "").strip()
        if not text:
            return ""

        fenced = re.search(r"```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]*?)```", text)
        if fenced:
            text = fenced.group(1).strip()

        return text.strip()

    def _build_fix_prompt(self, issue: SecurityIssue) -> str:
        vuln_type = self._vuln_type(issue)
        vulnerable_code = (issue.snippet or issue.evidence or issue.message or "").strip()
        return FIX_PROMPT_TEMPLATE.format(
            vuln_type=vuln_type,
            file_path=issue.file,
            line_number=issue.line,
            vulnerable_code=vulnerable_code,
        )

    async def _generate_fix_code(self, issue: SecurityIssue) -> str | None:
        vuln_type = self._vuln_type(issue)
        language = self._language_family(issue)
        deterministic = get_deterministic_fix(vuln_type, language)
        if deterministic:
            return deterministic

        if not self.enabled():
            return None

        prompt = self._build_fix_prompt(issue)

        if self.use_gemini:
            try:
                content = await self._generate_gemini_content(prompt)
                fix_code = self._sanitize_fix_code_output(content)
                if fix_code:
                    return fix_code
            except Exception:
                pass

        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": "Return only corrected replacement code. No markdown, comments, or explanations.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
                content = str(data["choices"][0]["message"]["content"])
            fix_code = self._sanitize_fix_code_output(content)
            return fix_code or None
        except Exception:
            return None

    @staticmethod
    def _extract_before_after(exact_fix: str) -> tuple[str, str]:
        text = str(exact_fix or "")
        before_match = re.search(r"before\s*[:\-]\s*([\s\S]*?)(?:after\s*[:\-]|$)", text, re.IGNORECASE)
        after_match = re.search(r"after\s*[:\-]\s*([\s\S]*?)(?:notes\s*[:\-]|$)", text, re.IGNORECASE)
        before = before_match.group(1).strip() if before_match else ""
        after = after_match.group(1).strip() if after_match else ""
        return before, after

    @staticmethod
    def _diff_line_count(before: str, after: str) -> int:
        before_lines = before.splitlines()
        after_lines = after.splitlines()
        diff = difflib.unified_diff(before_lines, after_lines, lineterm="")
        count = 0
        for line in diff:
            if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
                continue
            if line.startswith("+") or line.startswith("-"):
                count += 1
        return count

    @staticmethod
    def _looks_language_mismatched(issue: SecurityIssue, exact_fix: str) -> bool:
        file_path = (issue.file or "").lower()
        _, after = AIService._extract_before_after(exact_fix)
        code = after.lower()
        if not code:
            return True

        if file_path.endswith(".py") and any(token in code for token in ["const ", "let ", "=>", "function("]):
            return True
        if file_path.endswith((".js", ".ts", ".jsx", ".tsx")) and any(
            token in code for token in ["def ", "import os", "raise runtimeerror", "except exception"]
        ):
            return True
        return False

    @staticmethod
    def _template_for_common_issue(issue: SecurityIssue) -> AIGuidance | None:
        category = str(issue.category or "")
        evidence = (issue.evidence or issue.snippet or "").strip()

        if category == "Unsafe YAML Deserialization":
            load_match = re.search(r"yaml\.load\s*\(([^)]+)\)", evidence, re.IGNORECASE)
            load_arg = load_match.group(1).strip() if load_match else "data"
            return AIGuidance(
                explanation="Replace unsafe YAML loading with a safe loader.",
                danger="Unsafe deserialization can execute attacker-controlled objects.",
                real_world_example="Switch to yaml.safe_load for untrusted input.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    "After:\n"
                    f"yaml.safe_load({load_arg})\n\n"
                    "Notes:\nsafe_load prevents execution of arbitrary Python objects."
                ),
            )

        if category == "Unsafe Pickle Deserialization":
            return AIGuidance(
                explanation="Avoid deserializing untrusted data using pickle.",
                danger="Pickle can execute arbitrary code during deserialization.",
                real_world_example="Avoid pickle for untrusted input and use a safe format.",
                exact_fix=(
                    "Before:\npickle.load(file)\n\n"
                    "After:\n# Avoid pickle for untrusted input\n# Use JSON or another safe format instead\n\n"
                    "Notes:\nPickle can execute arbitrary code during deserialization.\nManual refactor may be required."
                ),
            )

        if category == "Server-Side Template Injection":
            return AIGuidance(
                explanation="User input is passed directly into render_template_string(), allowing template execution.",
                danger="An attacker can inject {{ config }} or {{ ''.__class__... }} to read secrets or achieve RCE.",
                real_world_example="Never pass user input into render_template_string. Use render_template with a static file.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    "After:\n"
                    "# Use render_template with a real template file - never render user input as a template\n"
                    "from flask import render_template\n"
                    "name = request.args.get('name', '')\n"
                    "# Sanitize or escape, then pass as a variable - NOT as template source\n"
                    "return render_template('greeting.html', name=name)\n\n"
                    "Notes:\nThis is critical severity if exploited - attacker can read env vars and achieve RCE."
                ),
            )

        if category == "Flask Debug Mode Enabled":
            evidence = (issue.evidence or issue.snippet or "").strip()
            return AIGuidance(
                explanation="Flask debug=True is hardcoded and must never reach production.",
                danger="Debug mode exposes an interactive debugger and Python console - attackers can execute arbitrary code on your server.",
                real_world_example="Disable debug in production (debug=false) and gate local debug behind an environment variable.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    "After:\n"
                    "import os\n"
                    "debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'\n"
                    "app.run(debug=debug_mode)\n\n"
                    "Notes:\nSet FLASK_DEBUG=false in production .env. Never hardcode True."
                ),
            )

        if category == "Hardcoded Secrets":
            evidence = (issue.evidence or issue.snippet or "# vulnerable line").strip()
            var_match = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]", evidence)
            var_symbol = var_match.group(1) if var_match else "secret"
            well_known_env_vars = {
                "accesskeyid": "AWS_ACCESS_KEY_ID",
                "secretaccesskey": "AWS_SECRET_ACCESS_KEY",
                "aws_access_key": "AWS_ACCESS_KEY_ID",
                "aws_secret": "AWS_SECRET_ACCESS_KEY",
                "stripe_secret": "STRIPE_SECRET_KEY",
                "stripe_key": "STRIPE_SECRET_KEY",
                "jwt_secret": "JWT_SECRET",
                "db_password": "DB_PASSWORD",
                "database_password": "DB_PASSWORD",
                "api_key": "API_KEY",
                "secret_key": "SECRET_KEY",
                "admin_token": "ADMIN_TOKEN",
            }
            env_var_name = well_known_env_vars.get(var_symbol.lower(), var_symbol.upper())
            is_js = str(issue.file or "").lower().endswith((".js", ".ts", ".jsx", ".tsx"))
            if is_js:
                after_code = f"const {var_symbol} = process.env.{env_var_name};"
            else:
                after_code = f"import os\n{var_symbol} = os.getenv(\"{env_var_name}\")"

            return AIGuidance(
                explanation="A hardcoded credential was found in source code.",
                danger="Hardcoded credentials leak through code access, logs, and build artifacts. Rotate immediately if already committed.",
                real_world_example="Load secrets from environment variables at runtime, never embed them in code.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    f"After:\n{after_code}\n\n"
                    f"Notes:\nSet {env_var_name} in your .env file. Rotate this credential if this repo is or was public."
                ),
            )

        if category == "SQL Injection":
            runtime = AIService._runtime_family(issue)
            var_match = re.search(
                r"['\"\s]\+\s*(\w+)"
                r"|f['\"].*\{(\w+)\}"
                r"|\$\{(\w+)\}",
                evidence,
            )
            param_var = "user_input"
            if var_match:
                param_var = next((g for g in var_match.groups() if g), "user_input")
            if runtime == "js":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "// Use parameterized query - pass values separately\n"
                    f"db.query('SELECT * FROM users WHERE id = ?', [{param_var}], (err, results) => {{\n"
                    "  res.json(results);\n"
                    "});\n\n"
                    "Notes:\nReplace ? with the appropriate placeholder for your DB driver "
                    "(? for mysql/sqlite3, $1 for pg). Never concatenate user input into SQL strings."
                )
            elif runtime == "go":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    'query := "SELECT * FROM users WHERE id = ?"\n'
                    "db.Query(query, userInput)\n\n"
                    "Notes:\nUse placeholders and pass untrusted values as query args."
                )
            elif runtime == "csharp":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "db.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE Id = {userInput}\");\n\n"
                    "Notes:\nUse parameterized EF APIs and avoid concatenated SQL strings."
                )
            else:
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    'query = "SELECT * FROM users WHERE id = %s"\n'
                    f"cursor.execute(query, ({param_var},))\n\n"
                    "Notes:\nUse placeholders and pass untrusted values as query args."
                )
            return AIGuidance(
                explanation="This query builds SQL using string concatenation, allowing an attacker to alter query logic.",
                danger="An attacker can bypass auth, extract all records, or delete data by injecting SQL fragments.",
                real_world_example="Pass user data as a query parameter, never as part of the SQL string.",
                exact_fix=exact_fix,
            )

        if category == "Dynamic Code Execution (eval/exec)":
            return AIGuidance(
                explanation="Remove unsafe eval usage.",
                danger="eval/exec can run attacker-controlled code.",
                real_world_example="Replace eval with safe parsing/validation logic.",
                exact_fix=(
                    "Before:\nresult = eval(user_input)\n\n"
                    "After:\n# Avoid eval; parse input safely instead\n\n"
                    "Notes:\nManual logic rewrite may be required depending on use case."
                ),
            )

        if category == "Command Injection":
            runtime = AIService._runtime_family(issue)
            evidence_lower = evidence.lower()
            cmd_context = "command"
            if "report" in evidence_lower:
                cmd_context = "report"
            elif "convert" in evidence_lower or "file" in evidence_lower:
                cmd_context = "file"
            elif "ping" in evidence_lower:
                cmd_context = "host"
            if runtime == "js":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "const { execFile } = require('child_process');\n"
                    "// Use execFile with an argument array - never exec with string concatenation\n"
                    "const ALLOWED = { ping: '/bin/ping' };\n"
                    "if (!ALLOWED[command]) return res.status(400).send('Invalid command');\n"
                    "execFile(ALLOWED[command], ['-c', '1', safeArg], (err, stdout) => {\n"
                    "  res.send(stdout);\n"
                    "});\n\n"
                    "Notes:\nNever pass user input directly to exec/execSync. Use execFile with an argument array and an allowlist."
                )
            elif runtime == "go":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "if !isAllowedBinary(binary) { return errors.New(\"invalid command\") }\n"
                    "exec.Command(binary, safeArg).Run()\n\n"
                    "Notes:\nAvoid shell invocation and enforce strict command allow-lists."
                )
            elif runtime == "csharp":
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "if (!AllowedCommands.Contains(cmd)) throw new InvalidOperationException();\n"
                    "var psi = new ProcessStartInfo(cmd) { UseShellExecute = false };\n"
                    "psi.ArgumentList.Add(safeArg);\n"
                    "Process.Start(psi);\n\n"
                    "Notes:\nValidate executable name and args separately; never pass raw shell text."
                )
            else:
                exact_fix = (
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"# Replace dynamic execution with an explicit allowlist\n"
                    f"ALLOWED_{cmd_context.upper()}S = {{'summary': ['python', 'reports/summary.py']}}\n"
                    "key = user_input.strip().lower()\n"
                    f"if key not in ALLOWED_{cmd_context.upper()}S:\n"
                    f"    raise ValueError('Invalid {cmd_context}')\n"
                    f"subprocess.run(ALLOWED_{cmd_context.upper()}S[key], check=True, shell=False)\n\n"
                    "Notes:\nNever pass user input to shell=True. Use an allowlist with shell=False."
                )
            return AIGuidance(
                explanation="User input reaches a command execution API without sanitization.",
                danger="An attacker can inject shell metacharacters to run arbitrary OS commands and read secrets.",
                real_world_example="Validate command input with an allowlist and use execFile/subprocess with shell=False instead of string-concatenated exec.",
                exact_fix=exact_fix,
            )

        if category == "Open Redirect":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "// Validate redirect destination against an allowlist\n"
                    "const ALLOWED_HOSTS = ['yourdomain.com', 'app.yourdomain.com'];\n"
                    "const parsed = new URL(next, 'https://yourdomain.com');\n"
                    "if (!ALLOWED_HOSTS.includes(parsed.hostname)) {\n"
                    "  return res.status(400).send('Invalid redirect destination');\n"
                    "}\n"
                    "res.redirect(next);"
                )
            else:
                after_code = (
                    "from urllib.parse import urlparse\n"
                    "ALLOWED_HOSTS = ['yourdomain.com']\n"
                    "parsed = urlparse(url)\n"
                    "if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                    "    return redirect('/')\n"
                    "return redirect(url)"
                )
            return AIGuidance(
                explanation="The redirect destination is taken directly from user input without validation.",
                danger="Attackers can redirect users to phishing sites to harvest credentials.",
                real_world_example="Validate the redirect URL against an allowlist of permitted hosts.",
                exact_fix=f"Before:\n{evidence}\n\nAfter:\n{after_code}\n\nNotes:\nNever trust a user-supplied redirect URL. Allowlist permitted destinations.",
            )

        if category == "Insecure CORS Configuration":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const cors = require('cors');\n"
                    "app.use(cors({\n"
                    "  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n"
                    "  credentials: false,\n"
                    "}));"
                )
            else:
                after_code = 'CORS(app, resources={r"/api/*": {"origins": ["https://yourdomain.com"]}}, supports_credentials=False)'
            return AIGuidance(
                explanation="CORS is configured to allow all origins, giving any website access to your API.",
                danger="Cross-origin requests from malicious sites can access authenticated API responses.",
                real_world_example="Explicitly allowlist permitted origins instead of using wildcard.",
                exact_fix=f"Before:\n{evidence}\n\nAfter:\n{after_code}\n\nNotes:\nList only the origins your frontend actually runs on.",
            )

        if category == "Credential in URL":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const serviceUser = process.env.SERVICE_USER;\n"
                    "const servicePass = process.env.SERVICE_PASSWORD;\n"
                    "const serviceBase = process.env.SERVICE_URL;\n"
                    "const url = serviceBase; // pass auth via headers or env-loaded client"
                )
            else:
                after_code = (
                    "service_user = os.getenv('SERVICE_USER')\n"
                    "service_pass = os.getenv('SERVICE_PASSWORD')\n"
                    "service_base = os.getenv('SERVICE_URL')\n"
                    "url = f\"{service_base}/resource\""
                )
            return AIGuidance(
                explanation="Credentials are embedded directly in a URL, leaking through logs and browser history.",
                danger="Logs, traces, and history expose these credentials, enabling immediate unauthorized access.",
                real_world_example="Load credentials from environment variables and pass via headers, not the URL.",
                exact_fix=f"Before:\n{evidence}\n\nAfter:\n{after_code}\n\nNotes:\nRotate the exposed credentials immediately if this repo is public.",
            )

        if category == "Unescaped HTML in Template (Potential XSS)":
            return AIGuidance(
                explanation="Avoid rendering unescaped HTML.",
                danger="Unescaped template rendering can enable XSS.",
                real_world_example="Render escaped values by default and sanitize when needed.",
                exact_fix=(
                    "Before:\n{{ user_input | safe }}\n\n"
                    "After:\n{{ user_input }}\n\n"
                    "Notes:\nEnsure content is sanitized if HTML rendering is required."
                ),
            )

        if category == "Exception Detail Exposure":
            return AIGuidance(
                explanation="Avoid exposing raw error messages.",
                danger="Detailed error text can leak internals useful to attackers.",
                real_world_example="Return generic errors to users and log details internally.",
                exact_fix=(
                    "Before:\nreturn str(e)\n\n"
                    "After:\nreturn \"An error occurred\"\n\n"
                    "Notes:\nLog detailed errors internally instead."
                ),
            )

        if category == "Weak Random Generator Usage":
            runtime = AIService._runtime_family(issue)
            evidence = (issue.evidence or issue.snippet or "").strip()
            if runtime == "js":
                after_code = (
                    "const { randomBytes } = require('crypto');\n"
                    "const token = randomBytes(32).toString('hex');  // cryptographically secure"
                )
            else:
                after_code = (
                    "import secrets\n"
                    "token = secrets.token_urlsafe(32)  # cryptographically secure"
                )
            return AIGuidance(
                explanation="A weak random generator is used where unpredictability is required.",
                danger="Math.random() and random.randint() are predictable and can be brute-forced for tokens and reset codes.",
                real_world_example="Use crypto.randomBytes() (Node.js) or secrets.token_urlsafe() (Python) for all security tokens.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    f"After:\n{after_code}\n\n"
                    "Notes:\nReplace all security-sensitive random calls."
                ),
            )

        if category == "Dependency Vulnerability":
            package = str(issue.package or "dependency")
            version = str(issue.package_version or "unknown")
            cve = str(issue.cve or "known advisory")
            target = str(issue.fix_version or "the latest patched release")
            before_dep, after_dep, notes = AIService._dependency_before_after(issue)
            return AIGuidance(
                explanation=f"{package}@{version} has a known vulnerability ({cve}).",
                danger="Known dependency vulnerabilities can be exploited through application code paths.",
                real_world_example=f"Upgrade {package} to {target} and verify transitive lockfile updates.",
                exact_fix=(
                    "Before:\n"
                    f"{before_dep}\n\n"
                    "After:\n"
                    f"{after_dep}\n\n"
                    "Notes:\n"
                    f"{notes}"
                ),
            )

        return None

    @staticmethod
    def _should_force_fallback(issue: SecurityIssue, candidate: AIGuidance) -> str | None:
        if AIService._normalized_confidence(candidate.confidence) == "Low":
            return "low-confidence"

        before, after = AIService._extract_before_after(candidate.exact_fix)
        if not before or not after:
            return "invalid-fix-format"

        if AIService._looks_language_mismatched(issue, candidate.exact_fix):
            return "language-mismatch"

        if AIService._diff_line_count(before, after) > 10:
            return "rewrite-too-large"

        return None

    @staticmethod
    def _normalized_confidence(value: str | None) -> str:
        raw = str(value or "").strip().lower()
        if raw in {"high", "h", "0.9", "1", "1.0"}:
            return "High"
        if raw in {"low", "l", "0.1", "0", "0.0"}:
            return "Low"
        return "Medium"

    @staticmethod
    def _format_strict_exact_fix(issue: SecurityIssue, candidate_exact_fix: str) -> str:
        # Always anchor the Before block to the real flagged evidence.
        evidence = (issue.evidence or issue.snippet or issue.message or "# Vulnerable code").strip()
        text = str(candidate_exact_fix or "")
        candidate_before, _ = AIService._extract_before_after(text)

        after_match = re.search(r"after\s*[:\-]\s*([\s\S]*?)(?:notes\s*[:\-]|$)", text, re.IGNORECASE)
        notes_match = re.search(r"notes\s*[:\-]\s*([\s\S]*)$", text, re.IGNORECASE)

        before = evidence
        if str(issue.category or "") == "Dependency Vulnerability" and candidate_before:
            before = candidate_before
        after = after_match.group(1).strip() if after_match else "Manual fix required"
        notes = notes_match.group(1).strip() if notes_match else "Verify fix with your test suite."

        return (
            "Fix Summary:\n"
            "Apply a minimal, targeted remediation to remove the vulnerable behavior while preserving original logic.\n\n"
            "Before:\n"
            f"{before}\n\n"
            "After:\n"
            f"{after}\n\n"
            "Notes:\n"
            f"{notes}"
        )

    @staticmethod
    def _with_policy_metadata(
        issue: SecurityIssue,
        guidance: AIGuidance,
        ai_used: bool = False,
        fallback_reason: str | None = None,
    ) -> AIGuidance:
        severity = str(issue.severity or "LOW").upper()
        category = str(issue.category or "")

        always_show_fix = {
            "Command Injection",
            "SQL Injection",
            "Credential in URL",
            "Weak Random Generator Usage",
            "Server-Side Template Injection",
            "Dynamic Code Execution (eval/exec)",
        }

        if severity in {"LOW", "INFO"} and category not in always_show_fix:
            return guidance.model_copy(
                update={
                    "exact_fix": "",
                    "guidance_type": "template-only",
                    "confidence": "High",
                    "fallback_reason": fallback_reason or "low-severity-template-policy",
                }
            )

        confidence = "Medium" if ai_used else "High"
        exact_fix = AIService._format_strict_exact_fix(issue, guidance.exact_fix)
        return guidance.model_copy(
            update={
                "exact_fix": exact_fix,
                "guidance_type": "full-safe",
                "confidence": confidence,
                "fallback_reason": fallback_reason,
            }
        )

    async def _throttle_if_needed(self) -> None:
        elapsed = time.time() - self._last_request_at
        wait = self.min_request_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)

    async def _generate_gemini_content(self, prompt: str) -> str:
        if not self.use_gemini or self._gemini_sdk is None:
            return ""

        await self._throttle_if_needed()

        last_error: Exception | None = None
        for model_name in self.gemini_model_candidates:
            client = self._gemini_sdk.GenerativeModel(model_name)

            def _call() -> str:
                response = client.generate_content(prompt)
                return (getattr(response, "text", "") or "").strip()

            try:
                content = await asyncio.to_thread(_call)
                self._last_request_at = time.time()
                self.gemini_model = model_name
                self._gemini_client = client
                return content
            except Exception as exc:
                last_error = exc
                continue

        if last_error:
            raise last_error
        return ""

    @staticmethod
    def _infer_language(path: str) -> str:
        lowered = (path or "").lower()
        if lowered.endswith(".py"):
            return "Python"
        if lowered.endswith(".js") or lowered.endswith(".jsx"):
            return "JavaScript"
        if lowered.endswith(".ts") or lowered.endswith(".tsx"):
            return "TypeScript"
        if lowered.endswith(".java"):
            return "Java"
        if lowered.endswith(".cs"):
            return "C#"
        if lowered.endswith(".go"):
            return "Go"
        if lowered.endswith(".rb"):
            return "Ruby"
        if lowered.endswith(".php"):
            return "PHP"
        return "the file language"

    @staticmethod
    def _xss_trigger(issue: SecurityIssue) -> str:
        blob = f"{issue.rule_id} {issue.message} {issue.evidence}".lower()
        if "|safe" in blob:
            return "|safe"
        if "dangerouslysetinnerhtml" in blob:
            return "dangerouslySetInnerHTML"
        if "innerhtml" in blob:
            return "innerHTML"
        if "mark_safe(" in blob:
            return "mark_safe"
        return "an unescaped HTML rendering path"

    @staticmethod
    def _severity_priority_text(issue: SecurityIssue) -> str:
        severity = str(issue.severity or "LOW").upper()
        if severity == "HIGH":
            return "Fix immediately"
        if severity == "MEDIUM":
            return "Fix in this release"
        return "Review before production; fix if input is user-controlled"

    @staticmethod
    def _command_trigger(issue: SecurityIssue) -> str:
        blob = f"{issue.rule_id} {issue.message} {issue.evidence}".lower()
        if "process.start" in blob:
            return "Process.Start"
        if "exec.command" in blob:
            return "exec.Command"
        if "shell=true" in blob:
            return "shell=True"
        if "os.system" in blob:
            return "os.system"
        if "subprocess" in blob:
            return "subprocess"
        return "dynamic command execution"

    @staticmethod
    def _sql_trigger(issue: SecurityIssue) -> str:
        blob = f"{issue.rule_id} {issue.message} {issue.evidence}".lower()
        if "fromsqlraw" in blob:
            return "FromSqlRaw"
        if "queryraw" in blob:
            return "QueryRaw"
        if "db.query" in blob:
            return "db.Query"
        if "cursor.execute" in blob:
            return "cursor.execute"
        if "select" in blob and "+" in blob:
            return "string-concatenated SQL"
        return "dynamic SQL construction"

    @staticmethod
    def _eval_trigger(issue: SecurityIssue) -> str:
        blob = f"{issue.rule_id} {issue.message} {issue.evidence}".lower()
        if "exec(" in blob:
            return "exec()"
        return "eval()"

    @staticmethod
    def _runtime_family(issue: SecurityIssue) -> str:
        path = (issue.file or "").lower()
        blob = f"{issue.rule_id} {issue.message} {issue.evidence}".lower()
        # File extension is the most reliable signal, so evaluate it first.
        if path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            return "js"
        if path.endswith(".py"):
            return "python"
        if path.endswith(".go") or "exec.command" in blob or "db.query" in blob:
            return "go"
        if path.endswith(".cs") or "fromsqlraw" in blob or "process.start" in blob:
            return "csharp"
        return "python"

    @staticmethod
    def _dependency_before_after(issue: SecurityIssue) -> tuple[str, str, str]:
        package = str(issue.package or "dependency")
        version = str(issue.package_version or "unknown")
        target = str(issue.fix_version or "latest patched release")
        manifest = str(issue.file or "").replace("\\", "/").lower()

        if manifest.endswith("go.mod"):
            return (
                f"require {package} {version}",
                f"require {package} {target}",
                "Run 'go get package@version' and 'go mod tidy', then run tests.",
            )

        if manifest.endswith(".csproj"):
            return (
                f"<PackageReference Include=\"{package}\" Version=\"{version}\" />",
                f"<PackageReference Include=\"{package}\" Version=\"{target}\" />",
                "Run 'dotnet restore' and your test suite after the upgrade.",
            )

        if manifest.endswith("packages.config"):
            return (
                f"<package id=\"{package}\" version=\"{version}\" />",
                f"<package id=\"{package}\" version=\"{target}\" />",
                "Restore NuGet packages and validate transitive dependency updates.",
            )

        return (
            f'"{package}": "{version}"',
            f'"{package}": "{target}"',
            "Run dependency update and test suite after upgrading.",
        )

    @staticmethod
    def _rule_based_fix(issue: SecurityIssue) -> AIGuidance | None:
        category = issue.category or "Weak Input Validation"
        evidence = (issue.evidence or issue.message or "# Vulnerable code").strip()
        priority_text = AIService._severity_priority_text(issue)

        if category == "Unescaped HTML in Template (Potential XSS)":
            trigger = AIService._xss_trigger(issue)
            trigger_desc = (
                f'The template uses the "{trigger}" construct, which disables escaping and renders raw HTML.'
                if trigger == "|safe"
                else f"The code uses {trigger}, which can render raw HTML without safe escaping."
            )
            return AIGuidance(
                explanation=trigger_desc,
                danger=(
                    "If user-controlled content reaches this path, attackers can inject browser-executed scripts (XSS). "
                    "Risk is typically bounded for LOW severity unless untrusted input is confirmed."
                ),
                real_world_example=(
                    f"Remove {trigger}, keep escaping enabled by default, and sanitize explicitly trusted HTML only. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "# Keep auto-escaping enabled and sanitize trusted rich text\n"
                    "safe_html = bleach.clean(content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)\n"
                    "rendered = template.render(content=safe_html)"
                ),
            )

        if category == "Flask Debug Mode Enabled":
            evidence = (issue.evidence or issue.snippet or "").strip()
            return AIGuidance(
                explanation="Flask is running with debug=True, which must never reach production.",
                danger="Debug mode exposes an interactive debugger/console - an attacker can execute arbitrary Python on your server.",
                real_world_example="Control debug mode via an environment variable, never hardcode True.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    "After:\n"
                    "import os\n"
                    "debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'\n"
                    "app.run(debug=debug_mode)\n\n"
                    "Notes:\nSet FLASK_DEBUG=false in your production .env. Default to off."
                ),
            )

        if category == "Unsafe YAML Deserialization":
            load_match = re.search(r"yaml\.load\s*\(([^)]+)\)", evidence, re.IGNORECASE)
            load_arg = load_match.group(1).strip() if load_match else "data"
            return AIGuidance(
                explanation=(
                    "This code uses yaml.load() with an unsafe loader, which can deserialize attacker-controlled objects. "
                    "In this path, the parser is handling untrusted data instead of a safe loader."
                ),
                danger=(
                    "An attacker can send crafted YAML to trigger remote code execution and take over the service. "
                    "This is critical when YAML input comes from requests, uploads, or external integrations."
                ),
                real_world_example="Use yaml.safe_load() for untrusted YAML and restrict accepted schema/fields before processing.",
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"yaml.safe_load({load_arg})\n\n"
                    "Notes:\nsafe_load prevents execution of arbitrary Python objects."
                ),
            )

        if category == "Unsafe Pickle Deserialization":
            return AIGuidance(
                explanation=(
                    "This code calls pickle.load()/pickle.loads() on data that is not guaranteed to be trusted. "
                    "Pickle deserialization executes embedded opcodes, not just data parsing."
                ),
                danger=(
                    "An attacker can execute arbitrary Python code and pivot into the host environment. "
                    "This becomes critical for data from APIs, queues, caches, or shared storage."
                ),
                real_world_example="Replace pickle with a safe format like JSON for untrusted payloads and validate structure before use.",
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "# Prefer JSON for untrusted payloads\n"
                    "obj = json.loads(serialized_data)\n"
                    "validate_payload(obj)"
                ),
            )

        if category == "Hardcoded Secrets":
            var_match = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]", evidence)
            var_symbol = var_match.group(1) if var_match else "secret"
            well_known_env_vars = {
                "accesskeyid": "AWS_ACCESS_KEY_ID",
                "secretaccesskey": "AWS_SECRET_ACCESS_KEY",
                "aws_access_key": "AWS_ACCESS_KEY_ID",
                "aws_secret": "AWS_SECRET_ACCESS_KEY",
                "stripe_secret": "STRIPE_SECRET_KEY",
                "stripe_key": "STRIPE_SECRET_KEY",
                "jwt_secret": "JWT_SECRET",
                "db_password": "DB_PASSWORD",
                "database_password": "DB_PASSWORD",
                "api_key": "API_KEY",
                "secret_key": "SECRET_KEY",
                "admin_token": "ADMIN_TOKEN",
            }
            env_var_name = well_known_env_vars.get(var_symbol.lower(), var_symbol.upper())
            return AIGuidance(
                explanation=(
                    "A secret value is hardcoded in code instead of being loaded from a secure runtime source. "
                    "This exposes credentials through repository access, logs, and build artifacts."
                ),
                danger=(
                    "Attackers can steal the key and access downstream services, data stores, or cloud APIs. "
                    "Risk is critical when the repository is shared, leaked, or CI output is exposed."
                ),
                real_world_example=(
                    "Move secrets to environment variables or a secret manager, and rotate exposed keys immediately. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "import os\n"
                    f"{var_symbol} = os.getenv(\"{env_var_name}\")\n"
                    f"if not {var_symbol}:\n"
                    f"    raise RuntimeError(\"{env_var_name} must be configured\")"
                ),
            )

        if category == "Command Injection":
            trigger = AIService._command_trigger(issue)
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const { execFile } = require('child_process');\n"
                    "const ALLOWED = { ping: '/bin/ping' };\n"
                    "if (!ALLOWED[command]) return res.status(400).send('Invalid command');\n"
                    "execFile(ALLOWED[command], ['-c', '1', safeArg], (err, stdout) => {\n"
                    "  res.send(stdout);\n"
                    "});"
                )
            else:
                after_code = (
                    "subprocess.run([\"command\", safe_arg], check=True, shell=False)"
                )
            return AIGuidance(
                explanation=(
                    "User-controlled input reaches command execution APIs such as subprocess with shell interpretation. "
                    f"The current path uses {trigger}, allowing injected shell tokens to alter command behavior."
                ),
                danger=(
                    "An attacker can run arbitrary OS commands, read secrets, and modify server state. "
                    "This is critical when request parameters are concatenated into shell commands."
                ),
                real_world_example=(
                    "Use argument arrays with shell=False and strict allow-list validation before execution."
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_code}"
                ),
            )

        if category == "SQL Injection":
            trigger = AIService._sql_trigger(issue)
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {\n"
                    "  res.json(results);\n"
                    "});"
                )
            elif runtime == "go":
                after_code = (
                    'query := "SELECT * FROM users WHERE id = ?"\n'
                    "db.Query(query, userInput)"
                )
            elif runtime == "csharp":
                after_code = (
                    "db.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE Id = {userInput}\");"
                )
            else:
                var_match = re.search(
                    r"(?:where\s+\w+\s*=\s*['\"]\s*'\s*\+\s*(\w+)"
                    r"|where\s+\w+\s*=\s*\"\s*\+\s*(\w+)"
                    r"|%\{(\w+)\}"
                    r"|=\s*(\w+)\s*\+)",
                    evidence,
                    re.IGNORECASE,
                )
                param_var = "user_input"
                if var_match:
                    param_var = next((group for group in var_match.groups() if group), "user_input")
                after_code = (
                    "query = \"SELECT * FROM users WHERE username = %s\"\n"
                    f"cursor.execute(query, ({param_var},))"
                )
            return AIGuidance(
                explanation=(
                    "This query path builds SQL using dynamic input instead of binding parameters safely. "
                    f"The {trigger} flow allows attackers to alter query structure rather than only supplying values."
                ),
                danger=(
                    "An attacker can bypass auth checks, extract sensitive records, or modify/delete data. "
                    "Critical impact appears in login, search, and reporting endpoints that accept user input."
                ),
                real_world_example=(
                    "Use parameterized queries/prepared statements and validate query inputs by type and length. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_code}"
                ),
            )

        if category == "Insecure Auth Logic":
            runtime = AIService._runtime_family(issue)
            evidence = (issue.evidence or issue.snippet or "").strip()
            if runtime == "js":
                return AIGuidance(
                    explanation="The authentication check uses assignment (=) instead of comparison (===), always evaluating to false.",
                    danger="An attacker can bypass authentication if this condition gates access control.",
                    real_world_example="Use strict equality === for all auth comparisons in JavaScript.",
                    exact_fix=(
                        f"Before:\n{evidence}\n\n"
                        "After:\n"
                        "if (auth === false) {  // use === not =\n"
                        "  // handle unauthenticated case\n"
                        "}\n\n"
                        "Notes:\nIn JS, = is assignment not comparison. Always use === for security checks."
                    ),
                )
            return AIGuidance(
                explanation="Insecure authentication logic detected.",
                danger="Weak auth checks can be bypassed by attackers.",
                real_world_example="Use constant-time comparison and proper boolean checks.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    "After:\n"
                    "import hmac\n"
                    "if not hmac.compare_digest(provided_password, expected_password):\n"
                    "    raise AuthError('Invalid credentials')\n\n"
                    "Notes:\nUse hmac.compare_digest to prevent timing attacks."
                ),
            )

        if category == "Open Redirect":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const ALLOWED_HOSTS = ['yourdomain.com', 'app.yourdomain.com'];\n"
                    "const parsed = new URL(next, 'https://yourdomain.com');\n"
                    "if (!ALLOWED_HOSTS.includes(parsed.hostname)) {\n"
                    "  return res.status(400).send('Invalid redirect destination');\n"
                    "}\n"
                    "res.redirect(next);"
                )
            else:
                after_code = (
                    "from urllib.parse import urlparse\n"
                    "ALLOWED_HOSTS = ['yourdomain.com']\n"
                    "parsed = urlparse(url)\n"
                    "if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                    "    return redirect('/')\n"
                    "return redirect(url)"
                )
            return AIGuidance(
                explanation=(
                    "The redirect destination is accepted from user input without validating the target host."
                ),
                danger=(
                    "Attackers can redirect users to phishing pages and steal credentials or tokens."
                ),
                real_world_example=(
                    "Allowlist redirect hosts and reject unknown destinations."
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_code}"
                ),
            )

        if category == "Dynamic Code Execution (eval/exec)":
            trigger = AIService._eval_trigger(issue)
            return AIGuidance(
                explanation=(
                    f"This code path invokes {trigger} on dynamic content, which executes code rather than parsing plain data."
                ),
                danger=(
                    "If the expression contains attacker-controlled input, this can lead to arbitrary code execution. "
                    "Impact is high for production services and automation workers."
                ),
                real_world_example=(
                    "Replace eval/exec with safe parsers and explicit allow-listed operations. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "# Use safe parsing instead of code execution\n"
                    "result = ast.literal_eval(value)"
                ),
            )

        if category == "Insecure CORS Configuration":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const cors = require('cors');\n"
                    "app.use(cors({\n"
                    "  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n"
                    "  credentials: false,\n"
                    "}));"
                )
            else:
                after_code = "CORS(app, resources={r\"/api/*\": {\"origins\": [\"https://app.example.com\"]}}, supports_credentials=False)"
            return AIGuidance(
                explanation=(
                    "CORS is enabled without explicit origin restrictions, allowing broad cross-origin access by default."
                ),
                danger=(
                    "Overly permissive CORS can expose authenticated API responses to malicious origins. "
                    "Severity is usually medium when credentials or sensitive endpoints are involved."
                ),
                real_world_example=(
                    "Set explicit allow-listed origins and disable credential sharing for untrusted domains. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_code}"
                ),
            )

        if category == "Credential in URL":
            runtime = AIService._runtime_family(issue)
            if runtime == "js":
                after_code = (
                    "const serviceUser = process.env.SERVICE_USER;\n"
                    "const servicePass = process.env.SERVICE_PASSWORD;\n"
                    "const serviceBase = process.env.SERVICE_URL;\n"
                    "const url = serviceBase;"
                )
            else:
                after_code = (
                    "service_user = os.getenv(\"SERVICE_USER\")\n"
                    "service_pass = os.getenv(\"SERVICE_PASSWORD\")\n"
                    "service_base = os.getenv(\"SERVICE_URL\")\n"
                    "url = f\"{service_base}/resource\""
                )
            return AIGuidance(
                explanation=(
                    "Credentials are embedded directly in a URL, which can leak through logs, traces, and browser history."
                ),
                danger=(
                    "Logs, traces, and browser history can leak URL credentials, enabling immediate unauthorized access "
                    "to internal or external services. "
                    "This should be treated as high severity and rotated quickly."
                ),
                real_world_example=(
                    "Remove credentials from URLs, load secrets from secure storage, and rotate exposed credentials. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_code}"
                ),
            )

        if category == "Weak Random Generator Usage":
            runtime = AIService._runtime_family(issue)
            evidence = (issue.evidence or issue.snippet or "").strip()
            if runtime == "js":
                after_code = (
                    "const { randomBytes } = require('crypto');\n"
                    "const token = randomBytes(32).toString('hex');  // cryptographically secure"
                )
            else:
                after_code = (
                    "import secrets\n"
                    "token = secrets.token_urlsafe(32)  # cryptographically secure"
                )
            return AIGuidance(
                explanation="A weak random generator is used where unpredictability is required.",
                danger="Math.random() and random.randint() are predictable and can be brute-forced for tokens and reset codes.",
                real_world_example="Use crypto.randomBytes() (Node.js) or secrets.token_urlsafe() (Python) for all security tokens.",
                exact_fix=(
                    f"Before:\n{evidence}\n\n"
                    f"After:\n{after_code}\n\n"
                    "Notes:\nReplace all security-sensitive random calls."
                ),
            )

        if category == "Exception Detail Exposure":
            return AIGuidance(
                explanation=(
                    "Raw exception details are returned to clients, exposing internal implementation and runtime state."
                ),
                danger=(
                    "Detailed errors can help attackers map backend internals and chain follow-on attacks. "
                    "This is medium severity for production APIs."
                ),
                real_world_example=(
                    "Log full exception details server-side and return a generic user-safe error message. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "logger.exception(\"Operation failed\")\n"
                    "return {\"error\": \"Request failed\"}, 500"
                ),
            )

        if category == "Insecure HTTP Usage":
            return AIGuidance(
                explanation=(
                    "A sensitive endpoint is configured over HTTP instead of HTTPS, allowing transport-layer interception."
                ),
                danger=(
                    "Attackers on the network can intercept credentials or tokens transmitted in clear text. "
                    "Severity is low-to-medium depending on endpoint sensitivity."
                ),
                real_world_example=(
                    "Switch endpoint URLs to HTTPS and enforce TLS validation in client requests. "
                    ""
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "endpoint = os.getenv(\"SERVICE_URL\")"
                ),
            )

        if category == "Debug Logging Hygiene":
            return AIGuidance(
                explanation=(
                    "Debug logging statements are present in this code path and may expose internal values in logs."
                ),
                danger=(
                    "Verbose logs can leak sensitive request or runtime context when enabled in production."
                ),
                real_world_example=(
                    "Remove debug-only logs from production paths or gate them behind controlled environment flags."
                ),
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    "if DEBUG_MODE:\n"
                    "    logger.debug(\"request metadata\")"
                ),
            )

        improvement_explanations = {
            "Hardcoded URL Configuration": (
                "Service endpoint is hardcoded in source code.",
                "Hardcoded endpoints make environment changes risky and can leak internal topology.",
                "Load endpoint values from environment configuration per deployment environment.",
            ),
            "Environment Secret Fallback": (
                "A secret environment variable has a hardcoded fallback value.",
                "Fallback secrets can accidentally reach production and weaken security controls.",
                "Require the environment value explicitly and fail fast if it is missing.",
            ),
            "Input Validation Coverage Hint": (
                "User-input handling path detected; validation intent is not explicit in this code path.",
                "Unchecked input can cause reliability or security defects depending on downstream usage.",
                "Add strict type/length/format validation before business logic execution.",
            ),
            "Weak Randomness Hygiene": (
                "Non-cryptographic random source appears in code.",
                "Predictable randomness can weaken security-sensitive flows like tokens and reset codes.",
                "Use the secrets module for security-sensitive random values.",
            ),
            "HTTPS Migration Opportunity": (
                "HTTP endpoint usage appears in the code path.",
                "Plain HTTP can expose traffic to interception on untrusted networks.",
                "Switch sensitive endpoints to HTTPS and enforce TLS validation.",
            ),
            "Large Function Complexity": (
                "Large function detected, increasing review and testing complexity.",
                "Complex functions are harder to secure, validate, and maintain.",
                "Split logic into smaller functions with explicit validation boundaries.",
            ),
            "Credential Placeholder Cleanup": (
                "Credential placeholder literal is present in source code.",
                "Placeholder credentials can accidentally ship and create insecure defaults.",
                "Replace placeholder values with required environment-managed secrets.",
            ),
            "Unused Import Hygiene": (
                "Large import list suggests potential unused dependencies.",
                "Unused imports add noise and can obscure security-relevant logic during review.",
                "Remove unused imports to improve clarity and reduce maintenance overhead.",
            ),
            "Error Boundary Coverage": (
                "Request handling path lacks explicit exception handling and safe fallback responses.",
                "Unhandled exceptions can leak internals to users and cause unstable API behavior under failure.",
                "Wrap handlers with explicit try/except and return consistent user-safe error responses.",
            ),
            "File Context Manager Hygiene": (
                "File operation appears without a context manager.",
                "Missing context managers can leak file handles and create unstable runtime behavior.",
                "Use context-managed file operations to guarantee cleanup.",
            ),
            "Rate Limiting Coverage Hint": (
                "Endpoint path detected without explicit rate-limiting signal.",
                "High-frequency abuse can impact reliability and amplify attack surface.",
                "Apply route-level rate limiting on sensitive and public endpoints.",
            ),
            "Critical Action Audit Logging": (
                "Sensitive operation path should include structured audit logging.",
                "Missing audit logs reduce traceability for security and incident response.",
                "Add structured logs for actor, target, and action outcome.",
            ),
            "Debug Mode Enabled (Improvement)": (
                "Debug mode setting was detected in code configuration.",
                "Debug settings can expose internals if accidentally enabled in production.",
                "Gate debug mode behind environment checks and disable in production.",
            ),
        }

        IMPROVEMENT_AFTER_BLOCKS: dict[str, str] = {
            "Hardcoded URL Configuration": (
                "SERVICE_URL = os.environ['SERVICE_URL']\n"
                "# Set SERVICE_URL in .env per environment, no hardcoded URL"
            ),
            "Environment Secret Fallback": (
                "SECRET = os.environ['SECRET_KEY']  # Raises KeyError if missing — no fallback"
            ),
            "Input Validation Coverage Hint": (
                "if not isinstance(user_input, str) or len(user_input) > 200:\n"
                "    raise ValueError('Invalid input')\n"
                "# Add type/length/format checks before business logic"
            ),
            "Weak Randomness Hygiene": (
                "import secrets\n"
                "token = secrets.token_urlsafe(32)  # Cryptographically secure"
            ),
            "HTTPS Migration Opportunity": (
                "endpoint = os.environ['SERVICE_URL']  # Configure an https:// endpoint in environment"
            ),
            "Large Function Complexity": (
                "def validate_input(data): ...\n"
                "def process_request(validated): ...\n"
                "# Split into smaller focused functions, each doing one thing"
            ),
            "Credential Placeholder Cleanup": (
                "API_KEY = os.getenv('API_KEY')  # Remove placeholder, load from environment"
            ),
            "Unused Import Hygiene": (
                "# Remove unused imports\n"
                "# Run: autoflake --remove-all-unused-imports -i yourfile.py"
            ),
            "Error Boundary Coverage": (
                "try:\n"
                "    result = process(request)\n"
                "except Exception:\n"
                "    logger.exception('Request failed')\n"
                "    return {'error': 'Request failed'}, 500"
            ),
            "File Context Manager Hygiene": (
                "with open(file_path, 'r') as f:\n"
                "    content = f.read()  # File handle closed automatically"
            ),
            "Rate Limiting Coverage Hint": (
                "from slowapi import Limiter\n"
                "limiter = Limiter(key_func=get_remote_address)\n"
                "@limiter.limit('10/minute')\n"
                "def your_route(): ..."
            ),
            "Critical Action Audit Logging": (
                "import logging\n"
                "logger = logging.getLogger(__name__)\n"
                "logger.info('Action performed', extra={'actor': user_id, 'target': resource_id, 'outcome': result})"
            ),
            "Debug Mode Enabled (Improvement)": (
                "debug_enabled = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'\n"
                "app.run(debug=debug_enabled)  # Never hardcode debug=True"
            ),
            "Broad Exception Handling": (
                "try:\n"
                "    result = risky_operation()\n"
                "except (ValueError, KeyError) as e:  # Catch specific exceptions\n"
                "    logger.warning('Expected error: %s', e)\n"
                "except Exception:\n"
                "    logger.exception('Unexpected error')\n"
                "    raise"
            ),
        }

        if category in improvement_explanations:
            problem, risk, preview = improvement_explanations[category]
            after_block = IMPROVEMENT_AFTER_BLOCKS.get(
                category,
                "# Apply the recommended fix for this category"
            )
            return AIGuidance(
                explanation=problem,
                danger=risk,
                real_world_example=preview,
                exact_fix=(
                    "Before:\n"
                    f"{evidence}\n\n"
                    "After:\n"
                    f"{after_block}\n\n"
                    "Notes:\n"
                    "Apply the minimal change above. Verify behaviour with your test suite."
                ),
            )

        if category == "Dependency Vulnerability":
            package = str(issue.package or "dependency")
            version = str(issue.package_version or "unknown")
            cve = str(issue.cve or "known advisory")
            target = str(issue.fix_version or "the latest patched release")
            before_dep, after_dep, notes = AIService._dependency_before_after(issue)
            return AIGuidance(
                explanation=f"{package}@{version} is flagged by security advisories ({cve}).",
                danger="Outdated dependencies can expose known exploit paths in production.",
                real_world_example=f"Upgrade {package} to {target} and refresh lockfiles.",
                exact_fix=(
                    "Before:\n"
                    f"{before_dep}\n\n"
                    "After:\n"
                    f"{after_dep}\n\n"
                    "Notes:\n"
                    f"{notes}"
                ),
            )

        return AIGuidance(
            explanation=(
                "Input validation is weak before data reaches a security-sensitive operation in this code path. "
                "The current checks do not enforce strict format or boundary constraints."
            ),
            danger=(
                "Attackers can pass malformed payloads that trigger unsafe behavior or chain into higher-impact attacks. "
                "Risk depends on where the input is used; prioritize validation before auth, file access, command, and database paths."
            ),
            real_world_example=(
                "Add strict allow-list validation and reject invalid input early with clear error handling. "
                ""
            ),
            exact_fix=(
                "Before:\n"
                f"{evidence}\n\n"
                "After:\n"
                "if not validator.is_valid(user_input):\n"
                "    raise ValueError(\"Invalid input\")"
            ),
        )

    @staticmethod
    def _is_generic_guidance(guidance: AIGuidance) -> bool:
        blob = (
            f"{guidance.explanation} {guidance.danger} "
            f"{guidance.real_world_example} {guidance.exact_fix}"
        ).lower()
        return any(marker in blob for marker in AIService._GENERIC_MARKERS)

    @staticmethod
    def _sanitize_user_facing_text(text: str) -> str:
        value = (text or "").strip()
        if not value:
            return value

        # Remove machine-specific absolute paths and scanner internal labels from user-facing text.
        value = re.sub(r"[A-Za-z]:\\[^\s\n\r\"']+", "application code", value)
        value = re.sub(r"(?:^|\s)/tmp/[^\s\n\r\"']+", " application code", value)
        value = re.sub(r"\brule\s*[:#-]?\s*[A-Za-z0-9_.-]+", "", value, flags=re.IGNORECASE)
        value = re.sub(r"\s+", " ", value).strip()
        return value

    @staticmethod
    def _is_weak_text(text: str) -> bool:
        value = (text or "").strip().lower()
        if not value:
            return True
        if any(marker in value for marker in AIService._GENERIC_MARKERS):
            return True
        return value in {"n/a", "none", "unknown"}

    @staticmethod
    def _enforce_guidance_quality(issue: SecurityIssue, guidance: AIGuidance) -> AIGuidance:
        fallback = AIService._fallback(issue)

        problem = AIService._sanitize_user_facing_text(guidance.explanation)
        risk = AIService._sanitize_user_facing_text(guidance.danger)
        fix_preview = AIService._sanitize_user_facing_text(guidance.real_world_example)
        exact_fix = guidance.exact_fix or ""

        if AIService._is_weak_text(problem):
            problem = fallback.explanation
        if AIService._is_weak_text(risk):
            risk = fallback.danger
        if AIService._is_weak_text(fix_preview):
            fix_preview = fallback.real_world_example
        if not AIService._has_fix_blocks(exact_fix):
            exact_fix = fallback.exact_fix

        return AIGuidance(
            explanation=problem,
            danger=risk,
            real_world_example=fix_preview,
            exact_fix=exact_fix,
            confidence=guidance.confidence,
            guidance_type=guidance.guidance_type,
            fallback_reason=guidance.fallback_reason,
        )

    @staticmethod
    def _fallback(issue: SecurityIssue) -> AIGuidance:
        template = AIService._template_for_common_issue(issue)
        guidance = template if template is not None else AIService._rule_based_fix(issue)
        base = AIGuidance(
            explanation=AIService._sanitize_user_facing_text(guidance.explanation),
            danger=AIService._sanitize_user_facing_text(guidance.danger),
            real_world_example=AIService._sanitize_user_facing_text(guidance.real_world_example),
            exact_fix=guidance.exact_fix,
            confidence="Medium",
            guidance_type="full-safe",
        )
        return AIService._with_policy_metadata(issue, base, ai_used=False, fallback_reason="deterministic-template")

    @staticmethod
    def _read_file_context(file_path: str, line: int, window: int = 5) -> str:
        try:
            from pathlib import Path as _Path

            lines = _Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, line - 1 - window)
            end = min(len(lines), line + window)
            result = []
            for i, l in enumerate(lines[start:end], start=start + 1):
                marker = ">>>" if i == line else "   "
                result.append(f"{marker} {i:4d}  {l}")
            return "\n".join(result)
        except Exception:
            return ""

    @staticmethod
    def _build_prompt(issue: SecurityIssue) -> str:
        language = AIService._infer_language(issue.file)
        context = AIService._read_file_context(issue.file, issue.line)
        context_block = (
            f"\nCode context (>>> marks the flagged line):\n{context}\n"
            if context
            else ""
        )
        return (
            "You are a senior security engineer generating a SAFE and MINIMAL fix. "
            "Return valid JSON only with keys: explanation, danger, real_world_example, exact_fix, confidence. "
            "Only suggest minimal line-level changes; do not rewrite whole functions. "
            "Use the EXACT variable names and code style visible in the context below. "
            "Do not add dependencies unless strictly necessary. Preserve original logic. "
            "If uncertain, include 'Manual fix required' in Notes. "
            "Never mention local machine paths or scanner rule IDs in user-facing fields. "
            "exact_fix must contain labeled blocks: 'Before:', 'After:', and 'Notes:'. "
            "The Before: block must show the actual vulnerable line from the evidence/context, not a generic example. "
            "confidence must be one of: High, Medium, Low.\n\n"
            f"Language: {language}\n"
            f"Category: {issue.category}\n"
            f"Severity: {issue.severity}\n"
            f"File: {issue.file} line {issue.line}\n"
            f"Data Source: {issue.data_source}\n"
            f"Usage Context: {issue.usage_context}\n"
            f"Flagged line: {issue.evidence}\n"
            f"Scanner message: {issue.message}"
            f"{context_block}"
            "\nKeep explanation to 1-2 sentences. Be concise and actionable."
        )

    @staticmethod
    def _has_fix_blocks(exact_fix: str) -> bool:
        text = (exact_fix or "").lower()
        return "before:" in text and "after:" in text

    @staticmethod
    def _merge_guidance(base: AIGuidance, candidate: AIGuidance) -> AIGuidance:
        explanation = AIService._sanitize_user_facing_text(candidate.explanation.strip()) or base.explanation
        danger = AIService._sanitize_user_facing_text(candidate.danger.strip()) or base.danger

        # Keep deterministic template fix direction as source of truth.
        real_world_example = base.real_world_example
        exact_fix = base.exact_fix

        if AIService._is_weak_text(explanation):
            explanation = base.explanation
        if AIService._is_weak_text(danger):
            danger = base.danger

        return AIGuidance(
            explanation=explanation,
            danger=danger,
            real_world_example=real_world_example,
            exact_fix=exact_fix,
            confidence=base.confidence,
            guidance_type=base.guidance_type,
        )

    @staticmethod
    def _extract_json_object(content: str) -> dict:
        text = (content or "").strip()
        if not text:
            return {}

        # First try direct JSON parsing.
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass

        # Handle markdown fenced code blocks.
        code_block = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text, re.IGNORECASE)
        if code_block:
            try:
                parsed = json.loads(code_block.group(1))
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass

        # Fallback: extract the largest JSON-looking object.
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start : end + 1]
            try:
                parsed = json.loads(candidate)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}

        return {}

    async def _generate_guidance(self, issue: SecurityIssue) -> AIGuidance:
        deterministic_guidance = self._fallback(issue)

        if str(issue.severity or "LOW").upper() in {"LOW", "INFO"}:
            return deterministic_guidance

        if not self.enabled():
            return deterministic_guidance

        key = self._cache_key(issue)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        if self.use_gemini:
            try:
                content = await self._generate_gemini_content(self._build_prompt(issue))
                parsed = self._extract_json_object(content)
                if parsed:
                    candidate = AIGuidance(
                        explanation=parsed.get("explanation", "No explanation returned."),
                        danger=parsed.get("danger", "No danger summary returned."),
                        real_world_example=parsed.get("real_world_example", "No example returned."),
                        exact_fix=parsed.get("exact_fix", "No fix returned."),
                        confidence=self._normalized_confidence(parsed.get("confidence")),
                        guidance_type="full-safe",
                    )
                    fallback_reason = self._should_force_fallback(issue, candidate)
                    if fallback_reason:
                        guidance = deterministic_guidance.model_copy(update={"fallback_reason": fallback_reason})
                        self._cache[key] = guidance
                        return guidance

                    guidance = self._enforce_guidance_quality(
                        issue,
                        self._merge_guidance(deterministic_guidance, candidate),
                    )
                    guidance = self._with_policy_metadata(issue, guidance, ai_used=True)
                    self._cache[key] = guidance
                    return guidance
            except Exception:
                # Continue to optional OpenAI-compatible path, then fallback.
                pass

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": "You explain code security findings simply for beginners.",
                },
                {
                    "role": "user",
                    "content": self._build_prompt(issue),
                },
            ],
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"]

            parsed = self._extract_json_object(content)
            if not parsed:
                return deterministic_guidance

            candidate = AIGuidance(
                explanation=parsed.get("explanation", "No explanation returned."),
                danger=parsed.get("danger", "No danger summary returned."),
                real_world_example=parsed.get("real_world_example", "No example returned."),
                exact_fix=parsed.get("exact_fix", "No fix returned."),
                confidence=self._normalized_confidence(parsed.get("confidence")),
                guidance_type="full-safe",
            )
            fallback_reason = self._should_force_fallback(issue, candidate)
            if fallback_reason:
                guidance = deterministic_guidance.model_copy(update={"fallback_reason": fallback_reason})
                self._cache[key] = guidance
                return guidance

            guidance = self._enforce_guidance_quality(
                issue,
                self._merge_guidance(deterministic_guidance, candidate),
            )
            guidance = self._with_policy_metadata(issue, guidance, ai_used=True)
            self._cache[key] = guidance
            return guidance
        except Exception:
            return deterministic_guidance

    async def enrich_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        enriched: List[SecurityIssue] = []
        for issue in issues:
            guidance = await self._generate_guidance(issue)
            if self._is_generic_guidance(guidance):
                guidance = self._fallback(issue)
            fix_code = await self._generate_fix_code(issue)
            snippet = (issue.snippet or issue.evidence or issue.message or "").strip()
            fix_description = issue.fix_description or guidance.real_world_example
            enriched.append(
                issue.model_copy(
                    update={
                        "guidance": guidance,
                        "snippet": snippet,
                        "fix_description": fix_description,
                        "fix_code": fix_code,
                    }
                )
            )
        return enriched

    def apply_deterministic_guidance(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        enriched: list[SecurityIssue] = []
        for issue in issues:
            guidance = self._fallback(issue)
            snippet = (issue.snippet or issue.evidence or issue.message or "").strip()
            fix_code = get_deterministic_fix(self._vuln_type(issue), self._language_family(issue))
            enriched.append(
                issue.model_copy(
                    update={
                        "guidance": guidance,
                        "snippet": snippet,
                        "fix_description": issue.fix_description or guidance.real_world_example,
                        "fix_code": fix_code,
                    }
                )
            )
        return enriched
