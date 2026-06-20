from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.routes.scan import _is_ai_candidate, _select_ai_candidates
from backend.services.ai_service import AIService


def _issue(title: str, severity: str) -> SecurityIssue:
    return SecurityIssue(
        title=title,
        severity=severity,
        file="app.py",
        line=10,
        scanner="regex",
        rule_id="regex.test",
        message="test message",
        category="Weak Input Validation",
        data_source="internal",
        usage_context="unknown",
        evidence="print('debug')",
        guidance=AIGuidance(
            explanation="x",
            danger="y",
            real_world_example="z",
            exact_fix="Before:\nold\n\nAfter:\nnew",
        ),
    )


def test_ai_candidate_policy_ignores_low() -> None:
    assert _is_ai_candidate(_issue("[LOW] Weak Input Validation", "LOW")) is False
    assert _is_ai_candidate(_issue("[INFO] Unused Import Hygiene", "INFO")) is False
    assert _is_ai_candidate(_issue("[MEDIUM] Weak Input Validation", "MEDIUM")) is True
    assert _is_ai_candidate(_issue("[HIGH] SQL Injection", "HIGH")) is True


def test_ai_candidate_selection_respects_budget_and_priority() -> None:
    issues = [
        _issue("[LOW] L", "LOW"),
        _issue("[MEDIUM] M1", "MEDIUM"),
        _issue("[HIGH] H1", "HIGH"),
        _issue("[MEDIUM] M2", "MEDIUM"),
    ]

    selected = _select_ai_candidates(issues, budget=2)

    assert len(selected) == 2
    assert selected[0].severity == "HIGH"
    assert selected[1].severity == "MEDIUM"


def test_ai_candidate_selection_prefers_higher_complexity_when_same_severity() -> None:
    low_complexity = _issue("[HIGH] Generic High", "HIGH").model_copy(
        update={
            "category": "Weak Input Validation",
            "message": "static check failed",
            "data_source": "internal",
            "usage_context": "unknown",
            "occurrence_count": 1,
        }
    )
    high_complexity = _issue("[HIGH] SQL Injection", "HIGH").model_copy(
        update={
            "category": "SQL Injection",
            "message": "query built from request payload",
            "data_source": "user_input",
            "usage_context": "database",
            "occurrence_count": 2,
        }
    )

    selected = _select_ai_candidates([low_complexity, high_complexity], budget=1)

    assert len(selected) == 1
    assert selected[0].category == "SQL Injection"


def test_deterministic_guidance_applies_without_ai() -> None:
    ai = AIService()
    low_issue = _issue("[LOW] Flask Debug Mode Enabled", "LOW").model_copy(
        update={"category": "Flask Debug Mode Enabled", "message": "app.run(debug=True)", "evidence": "app.run(debug=True)"}
    )

    applied = ai.apply_deterministic_guidance([low_issue])

    assert len(applied) == 1
    assert "debug" in applied[0].guidance.explanation.lower()
    assert "disable" in applied[0].guidance.real_world_example.lower() or "debug=false" in applied[0].guidance.real_world_example.lower()
    assert applied[0].guidance.guidance_type == "template-only"
    assert applied[0].guidance.confidence == "High"
    assert applied[0].guidance.exact_fix == ""


def test_template_locked_category_registry_includes_core_templates() -> None:
    assert AIService.is_template_locked_category("SQL Injection") is True
    assert AIService.is_template_locked_category("Unescaped HTML in Template (Potential XSS)") is True
    assert AIService.is_template_locked_category("Flask Debug Mode Enabled") is True


def test_template_locked_category_registry_excludes_non_core_templates() -> None:
    assert AIService.is_template_locked_category("Weak Input Validation") is False
    assert AIService.is_template_locked_category("Weak Random Generator Usage") is False


def test_confidence_normalization_returns_supported_values() -> None:
    ai = AIService()
    assert ai._normalized_confidence("high") == "High"
    assert ai._normalized_confidence("LOW") == "Low"
    assert ai._normalized_confidence("unexpected") == "Medium"


def test_fallback_triggered_on_low_confidence() -> None:
    ai = AIService()
    issue = _issue("[HIGH] SQL Injection", "HIGH").model_copy(
        update={"category": "SQL Injection", "file": "app.py"}
    )
    candidate = AIGuidance(
        explanation="x",
        danger="y",
        real_world_example="z",
        exact_fix="Before:\nquery = a + b\n\nAfter:\nquery = \"SELECT * FROM users WHERE id=%s\"\ncursor.execute(query, (user_input,))\n\nNotes:\nmanual review",
        confidence="Low",
        guidance_type="full-safe",
    )

    assert ai._should_force_fallback(issue, candidate) == "low-confidence"


def test_fallback_triggered_on_language_mismatch() -> None:
    ai = AIService()
    issue = _issue("[HIGH] SQL Injection", "HIGH").model_copy(
        update={"category": "SQL Injection", "file": "service.py"}
    )
    candidate = AIGuidance(
        explanation="x",
        danger="y",
        real_world_example="z",
        exact_fix="Before:\nvalue = request.args.get('id')\n\nAfter:\nconst value = req.query.id;\n\nNotes:\nmanual review",
        confidence="High",
        guidance_type="full-safe",
    )

    assert ai._should_force_fallback(issue, candidate) == "language-mismatch"


def test_fallback_triggered_on_oversized_rewrite() -> None:
    ai = AIService()
    issue = _issue("[HIGH] SQL Injection", "HIGH").model_copy(
        update={"category": "SQL Injection", "file": "app.py"}
    )
    before = "\n".join([f"line{i}" for i in range(1, 13)])
    after = "\n".join([f"new{i}" for i in range(1, 13)])
    candidate = AIGuidance(
        explanation="x",
        danger="y",
        real_world_example="z",
        exact_fix=f"Before:\n{before}\n\nAfter:\n{after}\n\nNotes:\nmanual review",
        confidence="High",
        guidance_type="full-safe",
    )

    assert ai._should_force_fallback(issue, candidate) == "rewrite-too-large"


def test_info_issue_guidance_remains_template_only_without_exact_fix() -> None:
    ai = AIService()
    info_issue = _issue("[INFO] Unused Import Hygiene", "INFO").model_copy(
        update={
            "category": "Unused Import Hygiene",
            "message": "large import list found",
            "evidence": "from os import path, getenv, listdir, walk",
        }
    )

    applied = ai.apply_deterministic_guidance([info_issue])

    assert len(applied) == 1
    assert applied[0].guidance.guidance_type == "template-only"
    assert applied[0].guidance.exact_fix == ""


def test_deterministic_guidance_sets_fix_fields_for_sql_issue() -> None:
    ai = AIService()
    sql_issue = _issue("[HIGH] SQL Injection", "HIGH").model_copy(
        update={
            "category": "SQL Injection",
            "file": "src/user.js",
            "evidence": "const q = `SELECT * FROM users WHERE id = ${userId}`;",
        }
    )

    applied = ai.apply_deterministic_guidance([sql_issue])

    assert len(applied) == 1
    assert applied[0].snippet != ""
    assert applied[0].fix_description is not None
    assert applied[0].fix_code is not None
