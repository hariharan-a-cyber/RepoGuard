from pathlib import Path

from backend.services.rule_engine import RuleEngine


def test_rule_engine_captures_multiple_matches_per_rule_in_one_file(tmp_path: Path) -> None:
    file_path = tmp_path / "api.js"
    file_path.write_text(
        """
        app.get('/users', (req, res) => {
          db.query("SELECT * FROM users WHERE id=" + req.query.id);
          db.query("SELECT * FROM users WHERE email='" + req.query.email + "'");
        });
        """,
        encoding="utf-8",
    )

    result = RuleEngine().scan_repository(tmp_path)
    sql_matches = [match for match in result.matches if match.rule_id == "regex.sql-injection"]

    assert len(sql_matches) == 2
    assert sql_matches[0].line != sql_matches[1].line
