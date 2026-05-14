"""
VoIP OSINT APEX — Centralized Configuration Manager
Single source of truth for all API keys, paths, and settings.
Replaces scattered load_dotenv() calls across modules.
"""

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

log = logging.getLogger("config")

# Load .env once at import time
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)


@dataclass
class APIKeys:
    """All external API keys — validated on startup."""
    ipqs: Optional[str] = None
    shodan: Optional[str] = None
    abuseipdb: Optional[str] = None
    virustotal: Optional[str] = None
    numverify: Optional[str] = None
    securitytrails: Optional[str] = None
    hibp: Optional[str] = None
    telegram_token: Optional[str] = None

    def __post_init__(self):
        self.ipqs = self._load("IPQS_KEY")
        self.shodan = self._load("SHODAN_KEY")
        self.abuseipdb = self._load("ABUSEIPDB_KEY")
        self.virustotal = self._load("VIRUSTOTAL_KEY")
        self.numverify = self._load("NUMVERIFY_KEY")
        self.securitytrails = self._load("SECURITYTRAILS_KEY")
        self.hibp = self._load("HIBP_KEY")
        self.telegram_token = self._load("TELEGRAM_BOT_TOKEN")

    @staticmethod
    def _load(env_var: str) -> Optional[str]:
        val = os.getenv(env_var, "").strip()
        if not val or val.startswith("your_"):
            return None
        return val

    def is_configured(self, key_name: str) -> bool:
        return getattr(self, key_name, None) is not None

    def report_status(self) -> dict[str, bool]:
        return {
            "ipqs": self.is_configured("ipqs"),
            "shodan": self.is_configured("shodan"),
            "abuseipdb": self.is_configured("abuseipdb"),
            "virustotal": self.is_configured("virustotal"),
            "numverify": self.is_configured("numverify"),
            "securitytrails": self.is_configured("securitytrails"),
            "hibp": self.is_configured("hibp"),
            "telegram_bot": self.is_configured("telegram_token"),
        }


@dataclass
class AppConfig:
    """Application-wide settings."""
    version: str = "3.0"
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    output_dir: Path = field(default_factory=lambda: Path("outputs"))
    cache_ttl: int = 3600          # 1 hour default
    feed_cache_ttl: int = 21600    # 6 hours for threat feeds
    http_timeout: int = 10         # seconds
    max_retries: int = 3
    debug: bool = False

    def __post_init__(self):
        self.debug = os.getenv("VOIP_DEBUG", "").lower() in ("1", "true", "yes")

    def ensure_output_dirs(self):
        """Create all required output directories."""
        dirs = [
            self.output_dir / "reports",
            self.output_dir / "logs",
            self.output_dir / "pcaps",
            self.output_dir / "subpoenas",
            self.output_dir / "feed_cache",
            self.output_dir / ".cache",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)


# ── Singleton instances ─────────────────────────────────────

_keys: Optional[APIKeys] = None
_config: Optional[AppConfig] = None


def get_keys() -> APIKeys:
    """Get the singleton API keys instance."""
    global _keys
    if _keys is None:
        _keys = APIKeys()
    return _keys


def get_config() -> AppConfig:
    """Get the singleton app config instance."""
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def print_key_status():
    """Log which API keys are configured vs missing."""
    keys = get_keys()
    status = keys.report_status()
    configured = [k for k, v in status.items() if v]
    missing = [k for k, v in status.items() if not v]

    if configured:
        log.info(f"[Config] API keys active: {', '.join(configured)}")
    if missing:
        log.warning(f"[Config] API keys missing: {', '.join(missing)} — some modules will be limited")
