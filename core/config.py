import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv
from loguru import logger

# Load .env file first
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class ScanConfig:
    default_rate_limit: int = 5
    default_timeout: int = 10
    max_redirects: int = 5
    user_agents: List[str] = field(default_factory=list)


@dataclass
class ScopeConfig:
    always_blocked: List[str] = field(default_factory=list)
    allowed_schemes: List[str] = field(default_factory=lambda: ["http", "https"])


@dataclass
class AppConfig:
    name: str = "WAPT Framework"
    version: str = "0.1.0"
    description: str = ""
    env: str = "development"
    secret_key: str = ""
    host: str = "0.0.0.0"
    port: int = 8000


@dataclass
class DBConfig:
    url: str = "sqlite+aiosqlite:///./wapt.db"


@dataclass
class LogConfig:
    level: str = "INFO"
    format: str = "{time} | {level} | {message}"
    rotation: str = "10 MB"
    retention: str = "7 days"
    file: str = "logs/wapt.log"


@dataclass
class Settings:
    app: AppConfig = field(default_factory=AppConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    db: DBConfig = field(default_factory=DBConfig)
    log: LogConfig = field(default_factory=LogConfig)
    report_output_dir: str = "reports/output"


def _load_yaml(path: Path) -> dict:
    """Load a YAML config file, return empty dict if not found."""
    if not path.exists():
        logger.warning(f"Config file not found at {path}, using defaults.")
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def load_settings() -> Settings:
    """
    Load and merge settings from:
    1. config.yaml  (base defaults)
    2. .env file    (environment overrides)
    """
    yaml_data = _load_yaml(BASE_DIR / "config.yaml")

    app_yaml = yaml_data.get("app", {})
    scan_yaml = yaml_data.get("scan", {})
    scope_yaml = yaml_data.get("scope", {})
    log_yaml = yaml_data.get("logging", {})

    settings = Settings(
        app=AppConfig(
            name=app_yaml.get("name", "WAPT Framework"),
            version=app_yaml.get("version", "0.1.0"),
            description=app_yaml.get("description", ""),
            env=os.getenv("APP_ENV", "development"),
            secret_key=os.getenv("SECRET_KEY", "insecure-default-change-me"),
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", 8000)),
        ),
        scan=ScanConfig(
            default_rate_limit=int(os.getenv(
                "DEFAULT_RATE_LIMIT",
                scan_yaml.get("default_rate_limit", 5)
            )),
            default_timeout=int(os.getenv(
                "DEFAULT_TIMEOUT",
                scan_yaml.get("default_timeout", 10)
            )),
            max_redirects=scan_yaml.get("max_redirects", 5),
            user_agents=scan_yaml.get("user_agents", [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            ]),
        ),
        scope=ScopeConfig(
            always_blocked=scope_yaml.get("always_blocked", []),
            allowed_schemes=scope_yaml.get("allowed_schemes", ["http", "https"]),
        ),
        db=DBConfig(
            url=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./wapt.db"),
        ),
        log=LogConfig(
            level=os.getenv("LOG_LEVEL", log_yaml.get("level", "INFO")),
            format=log_yaml.get("format", "{time} | {level} | {message}"),
            rotation=log_yaml.get("rotation", "10 MB"),
            retention=log_yaml.get("retention", "7 days"),
            file=os.getenv("LOG_FILE", "logs/wapt.log"),
        ),
        report_output_dir=os.getenv("REPORT_OUTPUT_DIR", "reports/output"),
    )

    return settings


# Single global instance — import this everywhere
settings = load_settings()