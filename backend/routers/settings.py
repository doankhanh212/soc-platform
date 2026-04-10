"""Settings API — quản lý cấu hình feed & platform qua giao diện web."""
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.settings_store import (
    get_feed_config,
    get_general_settings,
    load_settings,
    update_feed_config,
    update_general_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


# ── Models ────────────────────────────────────────────────────────────
class FeedUpdate(BaseModel):
    enabled: bool | None = None
    api_key: str | None = None
    cache_ttl: int | None = None
    sync_interval: int | None = None
    risk_threshold: float | None = None
    auto_block: bool | None = None


class GeneralUpdate(BaseModel):
    admin_whitelist_ips: str | None = None
    ssh_protected_port: int | None = None


# ── Feed endpoints ────────────────────────────────────────────────────
@router.get("/feeds")
async def list_feed_configs():
    """Trả về cấu hình tất cả feeds (API key bị mask)."""
    settings = load_settings()
    feeds = settings.get("feeds", {})
    result = {}
    for fid, cfg in feeds.items():
        safe = dict(cfg)
        # Mask API key — chỉ hiện 8 ký tự cuối
        raw_key = str(safe.get("api_key") or "")
        safe["api_key_preview"] = ("••••" + raw_key[-8:]) if len(raw_key) > 8 else ("••••" if raw_key else "")
        safe["has_api_key"] = bool(raw_key)
        safe.pop("api_key", None)
        result[fid] = safe
    return result


@router.get("/feeds/{feed_id}")
async def get_single_feed_config(feed_id: str):
    cfg = get_feed_config(feed_id)
    if not cfg:
        raise HTTPException(404, f"Feed '{feed_id}' không tồn tại")
    safe = dict(cfg)
    raw_key = str(safe.get("api_key") or "")
    safe["api_key_preview"] = ("••••" + raw_key[-8:]) if len(raw_key) > 8 else ("••••" if raw_key else "")
    safe["has_api_key"] = bool(raw_key)
    safe.pop("api_key", None)
    return safe


@router.put("/feeds/{feed_id}")
async def update_single_feed(feed_id: str, body: FeedUpdate):
    updates: dict[str, Any] = {}
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.api_key is not None:
        updates["api_key"] = body.api_key
    if body.cache_ttl is not None:
        if body.cache_ttl < 60:
            raise HTTPException(400, "cache_ttl phải >= 60 giây")
        updates["cache_ttl"] = body.cache_ttl
    if body.sync_interval is not None:
        if body.sync_interval < 5:
            raise HTTPException(400, "sync_interval phải >= 5 giây")
        updates["sync_interval"] = body.sync_interval
    if body.risk_threshold is not None:
        if not (0.0 <= body.risk_threshold <= 1.0):
            raise HTTPException(400, "risk_threshold phải nằm trong [0.0, 1.0]")
        updates["risk_threshold"] = body.risk_threshold
    if body.auto_block is not None:
        updates["auto_block"] = body.auto_block
    if not updates:
        raise HTTPException(400, "Không có trường nào để cập nhật")
    result = update_feed_config(feed_id, updates)
    # Mask key in response
    safe = dict(result)
    raw_key = str(safe.get("api_key") or "")
    safe["api_key_preview"] = ("••••" + raw_key[-8:]) if len(raw_key) > 8 else ("••••" if raw_key else "")
    safe["has_api_key"] = bool(raw_key)
    safe.pop("api_key", None)
    return {"ok": True, "feed": safe}


# ── General settings ──────────────────────────────────────────────────
@router.get("/general")
async def get_general():
    return get_general_settings()


@router.put("/general")
async def update_general(body: GeneralUpdate):
    updates: dict[str, Any] = {}
    if body.admin_whitelist_ips is not None:
        updates["admin_whitelist_ips"] = body.admin_whitelist_ips
    if body.ssh_protected_port is not None:
        if body.ssh_protected_port < 1 or body.ssh_protected_port > 65535:
            raise HTTPException(400, "Port không hợp lệ")
        updates["ssh_protected_port"] = body.ssh_protected_port
    if not updates:
        raise HTTPException(400, "Không có trường nào để cập nhật")
    result = update_general_settings(updates)
    return {"ok": True, "settings": result}
