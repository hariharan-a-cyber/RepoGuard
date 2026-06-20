import os
# SAFE: secrets pulled from environment, not hardcoded
API_KEY = os.environ.get("API_KEY")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
