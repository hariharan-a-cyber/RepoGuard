import json
from pathlib import Path

from backend.services.rule_engine import RuleEngine


def test_load_external_rules_appends_rules(tmp_path: Path) -> None:
    rules_dir = tmp_path / "backend" / "rules" / "node"
    rules_dir.mkdir(parents=True)
    rule_file = rules_dir / "sql_injection.json"
    rule_file.write_text(
        json.dumps(
            {
                "id": "node.sql_injection",
                "name": "SQL Injection",
                "language": "node",
                "pattern": "(SELECT|INSERT|UPDATE|DELETE)[^\\n;]*(\\+|`|\\$\\{)",
                "severity": "high",
                "description": "SQL query built by string concatenation — attacker can inject SQL.",
                "fix": "Use parameterized queries.",
            }
        ),
        encoding="utf-8",
    )

    engine = RuleEngine()
    before = len(engine.rules)

    engine.load_external_rules(str(tmp_path / "backend" / "rules"))

    assert len(engine.rules) == before + 1
    assert any(rule.rule_id == "node.sql_injection" for rule in engine.rules)


def test_external_rule_matches_in_scan_repository(tmp_path: Path) -> None:
    rules_dir = tmp_path / "backend" / "rules" / "node"
    rules_dir.mkdir(parents=True)
    (rules_dir / "sql_injection.json").write_text(
        json.dumps(
            {
                "id": "node.sql_injection",
                "name": "SQL Injection",
                "language": "node",
                "pattern": "(SELECT|INSERT|UPDATE|DELETE)[^\\n;]*(\\+|`|\\$\\{)",
                "severity": "high",
                "description": "SQL query built by string concatenation — attacker can inject SQL.",
                "fix": "Use parameterized queries.",
            }
        ),
        encoding="utf-8",
    )

    app_file = tmp_path / "app.js"
    app_file.write_text(
        "const q = `SELECT * FROM users WHERE id = ${userId}`;\n",
        encoding="utf-8",
    )

    engine = RuleEngine()
    engine.rules = []
    engine.load_external_rules(str(tmp_path / "backend" / "rules"))

    result = engine.scan_repository(tmp_path)

    assert any(match.rule_id == "node.sql_injection" for match in result.matches)
