import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    DB_USER = os.getenv("DB_USER", "tenex_user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "tenex_pass_dev")
    DB_NAME = os.getenv("DB_NAME", "tenex_logs")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")

    # Docker sets DATABASE_URL directly; local dev falls back to the DB_* pieces
    # pointed at localhost (the dockerized postgres port published to the host).
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
    )

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me")
    JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "480"))

    LLM_MODE = os.getenv("LLM_MODE", "hosted")  # "hosted" or "ollama"
    LLM_API_KEY = os.getenv("LLM_API_KEY")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    CORS_ORIGINS = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    ).split(",")
