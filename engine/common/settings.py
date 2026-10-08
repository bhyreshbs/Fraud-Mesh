# engine/common/settings.py  — reads env vars at import; values per Section 4
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "postgresql+psycopg://fm:fm@localhost:5432/fraudmesh"))
    hmac_secrets: dict = field(default_factory=lambda: json.loads(_env("HMAC_SECRETS", "{}")))
    token_key: str = field(default_factory=lambda: _env("TOKEN_KEY", "00" * 32))
    jwt_secret: str = field(default_factory=lambda: _env("JWT_SECRET", ""))
    base_rate: float = field(default_factory=lambda: float(_env("BASE_RATE", "0.01")))
    band_medium: float = field(default_factory=lambda: float(_env("BAND_MEDIUM", "0.20")))
    band_high: float = field(default_factory=lambda: float(_env("BAND_HIGH", "0.50")))
    band_critical: float = field(default_factory=lambda: float(_env("BAND_CRITICAL", "0.80")))
    model_dir: str = field(default_factory=lambda: _env("MODEL_DIR", "ml/artifacts"))
    demo_mode: bool = field(default_factory=lambda: _env("DEMO_MODE", "0") == "1")
    cors_origins: list = field(default_factory=lambda: [o for o in _env("CORS_ORIGINS", "").split(",") if o])
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))


settings = Settings()
