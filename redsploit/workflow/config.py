from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ScanSettings:
    default_timeout_seconds: int = 300
    max_concurrent_steps: int = 1
    per_host_concurrency: int = 5
    rate_limit_delay_ms: int = 0
    continuous_interval_hours: int = 720


@dataclass(slots=True)
class Settings:
    data_path: Path
    scan: ScanSettings = field(default_factory=ScanSettings)
    pd_project_id: str | None = None


_settings: Settings | None = None


def configure_settings(data_path: str | Path) -> Settings:
    global _settings
    path = Path(data_path).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    _settings = Settings(data_path=path)
    return _settings


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = configure_settings(Path.cwd() / ".redsploit-workflow")
    return _settings
