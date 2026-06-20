import pytest

from backend.services.github_service import GithubService, GithubServiceError


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://github.com/juice-shop/juice-shop", "https://github.com/juice-shop/juice-shop"),
        (" https://github.com/juice-shop/juice-shop/ ", "https://github.com/juice-shop/juice-shop"),
        ("https://github.com/juice-shop/juice-shop./", "https://github.com/juice-shop/juice-shop"),
    ],
)
def test_normalize_public_repo_url_accepts_and_canonicalizes(raw: str, expected: str) -> None:
    assert GithubService.normalize_public_repo_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "https://github.com/juice-shop",
        "https://github.com/juice-shop/juice-shop/issues",
        "http://github.com/juice-shop/juice-shop",
        "https://gitlab.com/juice-shop/juice-shop",
        "https://github.com/juice-shop/",
    ],
)
def test_normalize_public_repo_url_rejects_invalid_inputs(raw: str) -> None:
    with pytest.raises(GithubServiceError):
        GithubService.normalize_public_repo_url(raw)
