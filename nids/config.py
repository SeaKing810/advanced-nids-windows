from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, str(default)).strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    interface: str = os.getenv("NIDS_INTERFACE", "Wi-Fi")
    bpf_filter: str = os.getenv("NIDS_BPF_FILTER", "tcp or udp")

    db_path: str = os.getenv("DB_PATH", "data/nids.sqlite3")
    pcap_dir: str = os.getenv("PCAP_DIR", "pcaps")
    model_path: str = os.getenv("MODEL_PATH", "models/live_isoforest.joblib")

    log_encryption_key: str = os.getenv("LOG_ENCRYPTION_KEY", "")

    alerts_enabled: bool = _get_bool("ALERTS_ENABLED", True)
    alert_rate_limit_per_min: int = int(os.getenv("ALERT_RATE_LIMIT_PER_MIN", "6"))
    alert_cooldown_seconds: float = float(os.getenv("ALERT_COOLDOWN_SECONDS", "30"))

    twilio_enabled: bool = _get_bool("TWILIO_ENABLED", False)
    twilio_account_sid: str = os.getenv("TWILIO_ACCOUNT_SID", "")
    twilio_auth_token: str = os.getenv("TWILIO_AUTH_TOKEN", "")
    twilio_from_number: str = os.getenv("TWILIO_FROM_NUMBER", "")
    twilio_to_number: str = os.getenv("TWILIO_TO_NUMBER", "")

    smtp_enabled: bool = _get_bool("SMTP_ENABLED", False)
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from_email: str = os.getenv("SMTP_FROM_EMAIL", "")
    smtp_to_email: str = os.getenv("SMTP_TO_EMAIL", "")

    dash_username: str = os.getenv("DASH_USERNAME", "admin")
    dash_password: str = os.getenv("DASH_PASSWORD", "ChangeMeNow123!")
    jwt_secret: str = os.getenv("JWT_SECRET", "ChangeThisToALongRandomSecret")
    jwt_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "120"))


settings = Settings()
