"""
Persistent JSON settings store for feed configs & platform settings.
File: backend/data/platform_settings.json
Thread-safe read/write with a lock.
"""
import json
import threading
from pathlib import Path
from typing import Any

_SETTINGS_FILE = Path(__file__).resolve().parent.parent / "data" / "platform_settings.json"
_lock = threading.Lock()

_DEFAULTS: dict[str, Any] = {
    "feeds": {
        "abuseipdb": {
            "enabled": True,
            "api_key": "",
            "cache_ttl": 3600,
            "description": "IP reputation database",
        },
        "virustotal": {
            "enabled": False,
            "api_key": "",
            "description": "File & URL scanner",
        },
        "wazuh_suricata": {
            "enabled": True,
            "sync_interval": 10,
            "description": "IDS/HIDS alerts feed",
        },
        "ai_engine": {
            "enabled": True,
            "sync_interval": 60,
            "risk_threshold": 0.70,
            "auto_block": False,
            "description": "Anomaly detection từ AI",
        },
    },
    "general": {
        "admin_whitelist_ips": "",
        "ssh_protected_port": 22,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, keeping base keys that override doesn't have."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings() -> dict[str, Any]:
    with _lock:
        if _SETTINGS_FILE.exists():
            try:
                raw = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
                return _deep_merge(_DEFAULTS, raw)
            except (json.JSONDecodeError, OSError):
                pass
        return json.loads(json.dumps(_DEFAULTS))


def save_settings(data: dict[str, Any]) -> None:
    with _lock:
        _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SETTINGS_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def get_feed_config(feed_id: str) -> dict[str, Any]:
    settings = load_settings()
    return settings.get("feeds", {}).get(feed_id, {})


def update_feed_config(feed_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    settings = load_settings()
    feeds = settings.setdefault("feeds", {})
    current = feeds.get(feed_id, {})
    # Only allow updating known keys + keep description
    allowed_keys = {"enabled", "api_key", "cache_ttl", "sync_interval",
                    "risk_threshold", "auto_block", "description"}
    for k, v in updates.items():
        if k in allowed_keys:
            current[k] = v
    feeds[feed_id] = current
    save_settings(settings)
    return current


def get_general_settings() -> dict[str, Any]:
    settings = load_settings()
    return settings.get("general", {})


def update_general_settings(updates: dict[str, Any]) -> dict[str, Any]:
    settings = load_settings()
    general = settings.setdefault("general", {})
    allowed_keys = {"admin_whitelist_ips", "ssh_protected_port"}
    for k, v in updates.items():
        if k in allowed_keys:
            general[k] = v
    save_settings(settings)
    return general
