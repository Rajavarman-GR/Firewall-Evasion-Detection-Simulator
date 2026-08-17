import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///soc_simulator.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    ATTEMPT_THRESHOLDS = {"temporary": int(os.getenv("TEMP_BLOCK_THRESHOLD", "3")), "long": int(os.getenv("LONG_BLOCK_THRESHOLD", "5")), "permanent": int(os.getenv("PERMANENT_BLOCK_THRESHOLD", "10"))}
    TEMP_BLOCK_DURATION = int(os.getenv("TEMP_BLOCK_DURATION", "5"))
    LONG_BLOCK_DURATION = int(os.getenv("LONG_BLOCK_DURATION", "30"))
    CORRELATION_WINDOW = int(os.getenv("CORRELATION_WINDOW", "300"))
