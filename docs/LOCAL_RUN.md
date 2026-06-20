# Local Run Guide

## Prerequisites

- Python 3.10+
- `semgrep`
- `bandit`

## Setup

1. Create and activate virtual environment.

```powershell
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Configure environment.

```powershell
copy .env.example .env
```

4. Start backend.

```powershell
uvicorn backend.main:app --reload
```

## Local URLs

- App UI: `http://127.0.0.1:8000/`
- Health: `http://127.0.0.1:8000/health`
- OpenAPI: `http://127.0.0.1:8000/docs`

## Tests

```powershell
$env:PYTHONPATH='.'
pytest -q
```

## Common Issues

- `semgrep` missing: install and verify with `semgrep --version`.
- Auth/token errors: confirm `TOKEN_SECRET` and TTL env vars.
- CORS blocked: verify `CORS_ORIGINS` includes local origin.
