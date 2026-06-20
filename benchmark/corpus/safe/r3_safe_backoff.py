import random, time
def retry_delay(attempt):
    # SAFE: jitter for retry backoff, not security
    return (2 ** attempt) + random.random()
