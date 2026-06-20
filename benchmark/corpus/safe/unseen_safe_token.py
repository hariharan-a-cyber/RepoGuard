import secrets
def session_token():
    # SAFE: crypto-strong token
    return secrets.token_urlsafe(32)
