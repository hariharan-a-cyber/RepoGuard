from pathlib import Path


def test_pdf_service_removed_for_simplified_product() -> None:
    path = Path(__file__).resolve().parents[1] / "backend" / "services" / "pdf_service.py"
    assert path.exists() is False


def test_report_templates_removed_for_simplified_product() -> None:
    templates_dir = Path(__file__).resolve().parents[1] / "backend" / "templates"
    assert templates_dir.exists() is False
