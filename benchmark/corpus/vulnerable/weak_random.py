import random

def make_token():
    # VULN: non-crypto RNG for security token
    return random.randint(100000, 999999)
