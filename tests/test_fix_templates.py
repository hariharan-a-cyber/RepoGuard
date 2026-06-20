from backend.services.fix_templates import get_deterministic_fix, get_fix_description


def test_get_deterministic_fix_returns_language_specific_fix() -> None:
    fix = get_deterministic_fix("sql_injection", "node")
    assert fix is not None
    assert fix == "db.query('SELECT * FROM table WHERE id = ?', [userInput])"


def test_get_deterministic_fix_returns_language_specific_secret_fix() -> None:
    fix = get_deterministic_fix("hardcoded_secret", "python")
    assert fix is not None
    assert fix == "os.environ['SECRET_KEY']"


def test_get_deterministic_fix_returns_none_for_unknown_type() -> None:
    assert get_deterministic_fix("unknown_issue", "node") is None


def test_get_fix_description_returns_expected_text() -> None:
    desc = get_fix_description("dangerous_eval")
    assert "Replace eval/exec" in desc


def test_get_fix_description_returns_default_for_unknown_type() -> None:
    desc = get_fix_description("unknown_issue")
    assert desc == "Review and apply the recommended security fix before merging."
