# Release Checklist

## Security

- [ ] `.env` is not committed and production secrets are rotated.
- [ ] `TOKEN_SECRET` is strong and unique per environment.
- [ ] `ENABLE_LIFETIME_PRO_OVERRIDE=false` in production.
- [ ] `CORS_ORIGINS` only contains trusted domains.

## Reliability

- [ ] Full test suite passes.
- [ ] Semgrep and bandit are available on deployment target.
- [ ] API health endpoint returns `ok` after deploy.

## Product Readiness

- [ ] Auth flows tested: register, login, refresh, logout.
- [ ] Free vs paid limits validated.
- [ ] Scan report renders on desktop and mobile.

## Observability

- [ ] Runtime logs visible in deployment platform.
- [ ] Error alerts configured.
- [ ] Basic usage metrics captured (scans started/completed).

## Launch

- [ ] Landing copy and pricing reviewed.
- [ ] Support/contact channel visible.
- [ ] Rollback plan documented.
