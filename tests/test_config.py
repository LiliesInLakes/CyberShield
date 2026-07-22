from __future__ import annotations

import os
from pathlib import Path

from config import load, get_path, get_analysis, get_logging


def test_load_returns_dict():
    cfg = load()
    assert isinstance(cfg, dict)


def test_get_path_falls_back():
    val = get_path("nonexistent_key", "/fallback/path")
    assert val == "/fallback/path"


def test_get_path_env_override():
    os.environ["JADX_DIR"] = "/env/override"
    val = get_path("jadx_dir", "/default")
    assert val == "/env/override"
    del os.environ["JADX_DIR"]


def test_get_path_config_used():
    cfg = load()
    if "paths" in cfg and "jadx_dir" in cfg["paths"]:
        val = get_path("jadx_dir")
        assert val == cfg["paths"]["jadx_dir"]


def test_get_analysis_default():
    val = get_analysis("nonexistent", 42)
    assert val == 42


def test_get_logging_default():
    val = get_logging("nonexistent", "DEBUG")
    assert val == "DEBUG"
