from backend.services.github_check_run_service import github_check_run_service


def setup_function() -> None:
    github_check_run_service.reset_for_testing()


def test_start_check_run_prefers_existing_remote_match(monkeypatch) -> None:
    monkeypatch.setattr(
        github_check_run_service,
        "_find_existing_check_run",
        lambda **kwargs: 321,
    )

    updated: dict[str, int] = {"count": 0}

    def fake_update(**kwargs):
        updated["count"] += 1
        assert kwargs["check_run_id"] == 321
        assert kwargs["status"] == "in_progress"

    monkeypatch.setattr(github_check_run_service, "_update_check_run", fake_update)

    check_id = github_check_run_service.start_check_run(
        token="token",
        repository="acme/widget",
        commit_sha="abc123",
        external_id="repoguard:delivery:abc123",
        summary="queued",
    )

    assert check_id == 321
    assert updated["count"] == 1


def test_start_check_run_creates_when_no_existing_match(monkeypatch) -> None:
    monkeypatch.setattr(
        github_check_run_service,
        "_find_existing_check_run",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        github_check_run_service,
        "_create_check_run",
        lambda **kwargs: 555,
    )

    check_id = github_check_run_service.start_check_run(
        token="token",
        repository="acme/widget",
        commit_sha="abc124",
        external_id="repoguard:delivery:abc124",
        summary="queued",
    )

    assert check_id == 555
