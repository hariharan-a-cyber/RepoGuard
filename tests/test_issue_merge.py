from backend.models.scan_model import AIGuidance, SecurityIssue
from backend.routes.scan import _merge_duplicate_issues


def _issue(file_path: str, line: int) -> SecurityIssue:
    return SecurityIssue(
        title='[HIGH] Unsafe YAML Deserialization',
        severity='HIGH',
        file=file_path,
        line=line,
        scanner='semgrep',
        rule_id='yaml.load',
        message='yaml.load on request input',
        category='Unsafe YAML Deserialization',
        data_source='user_input',
        usage_context='parsed',
        evidence='obj = yaml.load(request.json)',
        guidance=AIGuidance(
            explanation='x',
            danger='y',
            real_world_example='z',
            exact_fix='Before:\nold\n\nAfter:\nnew',
        ),
    )


def test_merge_duplicates_counts_locations() -> None:
    merged = _merge_duplicate_issues([
        _issue('a.py', 10),
        _issue('b.py', 22),
    ])

    assert len(merged) == 2
    assert all(item.occurrence_count == 1 for item in merged)
