import secrets

def make_token():
    # SAFE: cryptographically secure RNG
    return secrets.token_hex(16)
