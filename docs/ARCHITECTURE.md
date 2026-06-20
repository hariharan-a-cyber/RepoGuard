# Architecture

## Overview

RepoGuard is a FastAPI-based web application that scans public repositories, normalizes security findings, enriches issues with exploitability context, and renders user-facing remediation guidance.

## Runtime Components

- `backend/main.py`: API app bootstrap and middleware setup.
- `backend/routes/`: HTTP route handlers (`scan`, `auth`, `feedback`, `metrics`, `validation`).
- `backend/services/`: business logic and scanner orchestration.
- `backend/models/scan_model.py`: Pydantic request/response contracts.
- `frontend/`: static web UI (HTML/CSS/JS).
- `data/reports/`: generated report artifacts.

## Scan Pipeline

1. Dependency scan parses manifests/lockfiles and checks advisories.
2. Rule engine runs deterministic code patterns.
3. Semgrep runs as primary external analyzer.
4. Bandit runs for Python repos when applicable.
5. Taint enrichment attaches source/sink/exploitability context.
6. AI/fallback guidance normalizes remediation content.
7. Response serializer returns issue list, risk score, and coverage metadata.

## Security/Auth

- Access and refresh tokens are signed and validated server-side.
- Refresh endpoint rotates tokens.
- Logout revokes active refresh tokens.
- CORS is configured from environment allowlist.

## Key Environment Variables

- `CORS_ORIGINS`
- `TOKEN_SECRET`
- `TOKEN_ACCESS_TTL_SECONDS`
- `TOKEN_REFRESH_TTL_SECONDS`
- `SEMGREP_TIMEOUT_SECONDS`
- `BANDIT_TIMEOUT_SECONDS`
- `MAX_FINDINGS`

## Folder Contract

- Keep generated files out of source folders.
- Keep scanner logic in `backend/services/`.
- Keep API contracts in `backend/models/`.
- Keep route handlers thin; business logic belongs in services.
