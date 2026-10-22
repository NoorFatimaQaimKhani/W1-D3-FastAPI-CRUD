from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from environment variables / the .env file.

    Real environment variables take priority over .env, which is how the
    test-suite points the app at SQLite without touching your PostgreSQL.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # old keys such as SECRET_KEY in .env are simply ignored
    )

    database_url: str

    redis_url: str = "redis://localhost:6379/0"

    jwt_private_key_path: str
    jwt_public_key_path: str

    jwt_issuer: str = "customer-records-api"
    jwt_audience: str = "customer-records-clients"
    access_token_expire_minutes: int = 30

    environment: str = "development"  
    sql_echo: bool = False 

    login_max_attempts: int = 5
    login_window_seconds: int = 900


settings = Settings()