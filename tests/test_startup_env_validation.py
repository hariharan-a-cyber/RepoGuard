import pytest

from backend import main


def test_production_requires_webhook_secret(monkeypatch) -> None:
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("GITHUB_APP_WEBHOOK_SECRET", raising=False)

    with pytest.raises(RuntimeError):
        main._required_production_env()


def test_non_production_does_not_require_webhook_secret(monkeypatch) -> None:
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("GITHUB_APP_WEBHOOK_SECRET", raising=False)

    main._required_production_env()
