from backend.services.taint_service import TaintFlow
from backend.services.scanner_service import ScannerService


def test_confidence_exact_with_context_validated_is_high() -> None:
    score = ScannerService._confidence_score(
        pattern_strength="exact",
        context_validated=True,
        file_path="src/auth/service.py",
        evidence="cursor.execute(query)",
    )
    assert score >= 85


def test_confidence_exact_without_context_in_expected_band() -> None:
    score = ScannerService._confidence_score(
        pattern_strength="exact",
        context_validated=False,
        file_path="src/service.py",
        evidence="query = base + suffix",
    )
    assert 70 <= score <= 85


def test_confidence_partial_pattern_in_expected_band() -> None:
    score = ScannerService._confidence_score(
        pattern_strength="partial",
        context_validated=False,
        file_path="src/module.py",
        evidence="possible risky pattern",
    )
    assert 50 <= score <= 70


def test_confidence_weak_pattern_is_low() -> None:
    score = ScannerService._confidence_score(
        pattern_strength="weak",
        context_validated=False,
        file_path="src/module.py",
        evidence="heuristic hint",
    )
    assert score < 60


def test_confidence_boost_is_capped_to_100() -> None:
    score = ScannerService._confidence_score(
        pattern_strength="exact",
        context_validated=True,
        file_path="config/auth/.env",
        evidence="eval(user_input); cursor.execute(sql)",
    )
    assert 0 <= score <= 100


def test_confidence_label_mapping() -> None:
    assert ScannerService._confidence_label(85) == "HIGH"
    assert ScannerService._confidence_label(60) == "MEDIUM"
    assert ScannerService._confidence_label(59) == "LOW"


def test_confidence_boost_respects_tier_cap() -> None:
    service = ScannerService()
    flow = TaintFlow(
        kind="sql_injection",
        file_path="server.js",
        line=10,
        source_symbol="req.body.id",
        sink_symbol="db.query",
        sanitized=False,
        framework="express",
        exploitability_level="HIGH",
    )

    boosted = service._confidence_boost_from_flow(90, flow)
    assert boosted <= 92


def test_confidence_boost_penalizes_deep_uncertain_flow() -> None:
    service = ScannerService()
    flow = TaintFlow(
        kind="sql_injection",
        file_path="server.js",
        line=10,
        source_symbol="req.body.id",
        sink_symbol="db.query",
        sanitized=False,
        framework="express",
        propagation_depth=2,
        uncertain=True,
        exploitability_level="MEDIUM",
    )

    boosted = service._confidence_boost_from_flow(72, flow)
    assert boosted <= 80
