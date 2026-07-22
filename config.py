from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ROOT_DIR = Path(__file__).resolve().parent
_CONFIG_PATH = ROOT_DIR / "config.yaml"
_config: dict[str, Any] | None = None


def load() -> dict[str, Any]:
    global _config
    if _config is not None:
        return _config
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            _config = yaml.safe_load(f)
    else:
        _config = {}
    return _config


def get_path(key: str, default: str = "") -> str:
    c = load()
    return os.environ.get(key.upper(), c.get("paths", {}).get(key, default))


def get_analysis(key: str, default: Any = None) -> Any:
    c = load()
    return c.get("analysis", {}).get(key, default)


def get_logging(key: str, default: Any = None) -> Any:
    c = load()
    return c.get("logging", {}).get(key, default)
