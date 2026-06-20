from backend.models.scan_model import AIGuidance
from backend.services.ai_service import AIService
from backend.services.scanner_service import ScannerService


def _issue(category_hint: str, code: str, message: str):
    scanner = ScannerService()
    return scanner._finalize_issue(
        scanner="semgrep",
        rule_id=category_hint,
        scanner_title="rule",
        scanner_severity="LOW",
        file_path="service.py",
        line=12,
        message=message,
        code_snippet=code,
    )


def test_guidance_contains_required_sections_and_fix_blocks() -> None:
    ai = AIService()
    issue = _issue("yaml.load", "obj = yaml.load(request.json)", "unsafe yaml load")

    guidance = ai._fallback(issue)

    assert "yaml" in guidance.explanation.lower()
    assert "arbitrary" in guidance.danger.lower() or "execute" in guidance.danger.lower()
    assert "safe_load" in guidance.real_world_example or "safe loader" in guidance.real_world_example.lower()
    assert "Before:" in guidance.exact_fix
    assert "After:" in guidance.exact_fix
    assert "Notes:" in guidance.exact_fix


def test_guidance_uses_category_specific_content() -> None:
    ai = AIService()
    yaml_issue = _issue("yaml.load", "obj = yaml.load(request.json)", "yaml parse")
    pickle_issue = _issue("pickle.loads", "obj = pickle.loads(request.data)", "pickle parse")

    yaml_guidance = ai._fallback(yaml_issue)
    pickle_guidance = ai._fallback(pickle_issue)

    assert "yaml" in yaml_guidance.explanation.lower()
    assert "pickle" in pickle_guidance.explanation.lower()
    assert "yaml.safe_load" in yaml_guidance.exact_fix
    assert "use json" in pickle_guidance.exact_fix.lower() or "json" in pickle_guidance.exact_fix.lower()
    assert "yaml.safe_load" not in pickle_guidance.exact_fix


def test_flask_debug_mode_guidance_is_specific_and_actionable() -> None:
    ai = AIService()
    issue = _issue("flask-debug", "app.run(debug=True)", "Flask app running with debug=True")

    guidance = ai._fallback(issue)

    assert "debug=true" in guidance.explanation.lower() or "debug mode" in guidance.explanation.lower()
    assert "interactive debugger" in guidance.danger.lower() or "stack traces" in guidance.danger.lower()
    assert "debug=false" in guidance.real_world_example.lower() or "disable debug" in guidance.real_world_example.lower()
    assert guidance.guidance_type == "template-only"
    assert guidance.confidence == "High"
    assert guidance.exact_fix == ""


def test_guidance_quality_guardrails_remove_internal_noise() -> None:
    ai = AIService()
    issue = _issue("flask-debug", "app.run(debug=True)", "rule flask-debug in C:\\Users\\dev\\temp\\repo\\app.py")

    candidate = AIGuidance(
        explanation="Rule bandit.B201 in C:\\Users\\dev\\repo\\app.py indicates risk",
        danger="No explanation returned.",
        real_world_example="Apply secure coding practices for this finding.",
        exact_fix="not parseable",
    )
    enforced = ai._enforce_guidance_quality(issue, ai._merge_guidance(ai._fallback(issue), candidate))

    blob = f"{enforced.explanation} {enforced.danger} {enforced.real_world_example}".lower()
    assert "c:\\users\\" not in blob
    assert "rule bandit" not in blob
    assert "no explanation returned" not in blob
    assert "secure coding practices" not in blob


def test_template_safe_guidance_mentions_trigger_and_actionable_fix() -> None:
    ai = AIService()
    issue = _issue("jinja.safe", "{{ user_bio|safe }}", "template uses |safe filter")

    guidance = ai._fallback(issue)

    assert "unescaped html" in guidance.explanation.lower() or "escaped" in guidance.real_world_example.lower()
    assert "user-controlled" in guidance.danger.lower() or "xss" in guidance.danger.lower()
    assert "sanitize" in guidance.real_world_example.lower() or "escaped" in guidance.real_world_example.lower()
    assert guidance.guidance_type == "template-only"


def test_command_injection_guidance_mentions_trigger_and_priority() -> None:
    ai = AIService()
    issue = _issue("subprocess.shell", "subprocess.run(cmd, shell=True)", "command built from request arg")

    guidance = ai._fallback(issue)

    assert "commands" in guidance.explanation.lower() or "command" in guidance.danger.lower()
    assert "input" in guidance.danger.lower() or "command" in guidance.danger.lower()
    assert "validate" in guidance.real_world_example.lower() or "shell=false" in guidance.real_world_example.lower()
    assert "Before:" in guidance.exact_fix
    assert "After:" in guidance.exact_fix
    assert "Notes:" in guidance.exact_fix
    assert guidance.guidance_type == "full-safe"
    assert guidance.confidence in {"Medium", "High"}


def test_credential_url_guidance_is_actionable() -> None:
    ai = AIService()
    issue = _issue(
        "regex.credential-url",
        'url = "https://user:pass@example.internal/api"',
        "credentials embedded directly in url",
    )

    guidance = ai._fallback(issue)

    assert "credentials" in guidance.explanation.lower()
    assert "logs" in guidance.danger.lower() or "history" in guidance.danger.lower() or "credentials" in guidance.danger.lower()
    assert "rotate" in guidance.real_world_example.lower() or "environment" in guidance.real_world_example.lower()
    assert "Before:" in guidance.exact_fix
    assert "After:" in guidance.exact_fix


def test_fallback_guidance_contains_deterministic_reason() -> None:
    ai = AIService()
    issue = _issue("yaml.load", "obj = yaml.load(request.json)", "unsafe yaml load")

    guidance = ai._fallback(issue)

    assert guidance.fallback_reason == "deterministic-template"


def test_debug_logging_guidance_is_not_generic_input_validation_text() -> None:
    ai = AIService()
    issue = _issue(
        "semgrep.custom.logging",
        "console.log(request.headers.authorization)",
        "debug logging in request path",
    )

    guidance = ai._fallback(issue)

    assert issue.category == "Debug Logging Hygiene"
    assert "input validation is weak" not in guidance.explanation.lower()
    assert "log" in guidance.explanation.lower() or "debug" in guidance.explanation.lower()


def test_dependency_guidance_is_specific_not_generic_input_validation() -> None:
    ai = AIService()
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "multer",
            "version": "1.4.5-lts.1",
            "cve": "CVE-2024-1111",
            "issue": "Known vulnerable dependency",
            "fix": "Upgrade to patched version",
            "fix_version": "2.0.0",
            "manifest_path": "package.json",
            "confidence": 100,
        }
    )

    guidance = ai._fallback(issue)

    assert "input validation is weak" not in guidance.explanation.lower()
    assert "vulnerab" in guidance.explanation.lower() or "advisory" in guidance.explanation.lower()
    assert "upgrade" in guidance.real_world_example.lower()


def test_dependency_guidance_uses_go_mod_format_when_manifest_is_go_mod() -> None:
    ai = AIService()
    scanner = ScannerService()
    issue = scanner._dependency_issue(
        {
            "severity": "HIGH",
            "package": "golang.org/x/crypto",
            "version": "v0.12.0",
            "cve": "CVE-2025-9999",
            "issue": "Known vulnerable dependency",
            "fix": "Upgrade to patched version",
            "fix_version": "v0.31.0",
            "manifest_path": "go.mod",
            "confidence": 100,
        }
    )

    guidance = ai._fallback(issue)

    assert "Before:" in guidance.exact_fix
    assert "After:" in guidance.exact_fix
    assert "require golang.org/x/crypto v0.12.0" in guidance.exact_fix
    assert "require golang.org/x/crypto v0.31.0" in guidance.exact_fix
    assert "go mod tidy" in guidance.exact_fix


def test_sql_injection_guidance_uses_csharp_fix_for_cs_files() -> None:
    ai = AIService()
    issue = _issue(
        "semgrep.csharp.sql",
        "db.Users.FromSqlRaw(sql)",
        "query uses string concatenation",
    ).model_copy(
        update={
            "file": "Repository/UserRepo.cs",
            "category": "SQL Injection",
        }
    )

    guidance = ai._fallback(issue)

    assert "FromSqlInterpolated" in guidance.exact_fix
    assert "FromSqlRaw" in guidance.exact_fix


def test_command_injection_guidance_uses_csharp_fix_for_cs_files() -> None:
    ai = AIService()
    issue = _issue(
        "semgrep.csharp.command",
        "Process.Start(userInput)",
        "command built from raw input",
    ).model_copy(
        update={
            "file": "Jobs/Runner.cs",
            "category": "Command Injection",
        }
    )

    guidance = ai._fallback(issue)

    assert "ProcessStartInfo" in guidance.exact_fix
    assert "AllowedCommands" in guidance.exact_fix


def test_command_injection_python_template_does_not_execute_raw_user_input() -> None:
    ai = AIService()
    issue = _issue(
        "semgrep.python.command",
        "os.system(user_input)",
        "command built from request argument",
    ).model_copy(
        update={
            "file": "worker/tasks.py",
            "category": "Command Injection",
        }
    )

    guidance = ai._fallback(issue)
    exact_fix_lower = guidance.exact_fix.lower()

    assert "subprocess.run([user_input]" not in exact_fix_lower
    assert "allowed" in exact_fix_lower
    assert "invalid command" in exact_fix_lower
