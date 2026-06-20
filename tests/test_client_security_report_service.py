from pathlib import Path


def test_client_security_report_service_removed_for_simplification() -> None:
    path = Path(__file__).resolve().parents[1] / "backend" / "services" / "client_security_report_service.py"
    assert path.exists() is False
