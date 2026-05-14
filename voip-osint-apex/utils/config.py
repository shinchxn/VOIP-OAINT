"""
VoIP OSINT APEX v3.0 — Centralized Configuration Manager
Single source of truth for all API keys, paths, and settings.
Replaces scattered load_dotenv() calls across modules.
"""

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv
from utils.exceptions import APIKeyMissingError

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

    def __post_init__(self):
        self.ipqs          = self._load("IPQS_KEY")
        self.shodan        = self._load("SHODAN_KEY")
        self.abuseipdb     = self._load("ABUSEIPDB_KEY")
        self.virustotal    = self._load("VIRUSTOTAL_KEY")
        self.numverify     = self._load("NUMVERIFY_KEY")
        self.securitytrails = self._load("SECURITYTRAILS_KEY")
        self.hibp          = self._load("HIBP_KEY")

    @staticmethod
    def _load(env_var: str) -> Optional[str]:
        val = os.getenv(env_var, "").strip()
        if not val or val.startswith("your_"):
            return None
        return val

    def get(self, key_name: str, required: bool = False) -> Optional[str]:
        """
        Get a key value by name.
        Raises APIKeyMissingError if required=True and key not set.
        """
        val = getattr(self, key_name, None)
        if required and val is None:
            raise APIKeyMissingError(key_name)
        return val

    def is_configured(self, key_name: str) -> bool:
        return getattr(self, key_name, None) is not None

    def status(self) -> dict[str, str]:
        """Returns {key_name: 'SET'/'MISSING'} for all keys."""
        keys = ["ipqs", "shodan", "abuseipdb", "virustotal",
                "numverify", "securitytrails", "hibp"]
        return {k: ("SET" if getattr(self, k) else "MISSING") for k in keys}

    def report_status(self) -> dict[str, bool]:
        """Returns {key_name: bool} for all keys."""
        return {k: (v == "SET") for k, v in self.status().items()}


@dataclass
class AppConfig:
    """Application-wide settings."""
    version: str = "3.0"
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    output_dir: Path = field(default_factory=lambda: Path("outputs"))
    cache_ttl: int = 3600           # 1 hour default
    feed_cache_ttl: int = 21600     # 6 hours for threat feeds
    http_timeout: int = 10          # seconds
    max_retries: int = 3
    debug: bool = False
    redis_host: str = "localhost"
    redis_port: int = 6379

    def __post_init__(self):
        self.debug      = os.getenv("VOIP_DEBUG", "").lower() in ("1", "true", "yes")
        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        output_env = os.getenv("VOIP_OUTPUT_DIR", "")
        if output_env:
            self.output_dir = Path(output_env)

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
    status = keys.status()
    configured = [k for k, v in status.items() if v == "SET"]
    missing    = [k for k, v in status.items() if v == "MISSING"]

    if configured:
        log.info(f"[Config] API keys active: {', '.join(configured)}")
    if missing:
        log.warning(f"[Config] API keys missing: {', '.join(missing)} — some modules will be limited")
