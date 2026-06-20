import logging
def audit(action):
    # SAFE: 'SELECT' appears in a log string, no query built
    logging.info("User ran a SELECT-style report for " + action)
