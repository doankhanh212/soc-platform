import asyncio
import re
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query

from config import get_settings
from services import get_ai_anomaly_alerts, get_recent_alerts

# Cache AbuseIPDB result 1 giờ để không bị rate-limit (1000 req/ngày free)
_ABUSEIPDB_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 3600  # seconds


router = APIRouter(prefix="/api/threatintel", tags=["threat-intel"])

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

COUNTRY_CODE = {
    "Myanmar": "MM",
    "United States": "US",
    "Netherlands": "NL",
    "Vietnam": "VN",
    "Unknown": "UN",
}

MODEL_LABELS = {
    "IsolationForest": "Hành vi bất thường",
    "EWMA": "Tăng đột biến",
    "CUSUM": "Leo thang âm thầm",
    "Entropy": "Dữ liệu mã hóa / ẩn",
}


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


async def _fetch_abuseipdb(ip: str) -> dict[str, Any] | None:
    """Gọi AbuseIPDB v2 /check. Trả None nếu không có key hoặc lỗi."""
    import time
    s = get_settings()
    if not s.abuseipdb_api_key:
        return None

    # Kiểm tra cache
    cached = _ABUSEIPDB_CACHE.get(ip)
    if cached and (time.time() - cached[0]) < _CACHE_TTL:
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": s.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        _ABUSEIPDB_CACHE[ip] = (time.time(), data)
        return data
    except Exception:
        return None


@router.get("/lookup")
async def lookup_ip(q: str = Query(..., min_length=1)):
    query = q.strip()
    if not IP_RE.match(query):
        raise HTTPException(status_code=404, detail=f"Không có dữ liệu threat intel cho: {query}")

    # Chạy song song: lấy dữ liệu nội bộ + gọi AbuseIPDB
    (wazuh_alerts, ai_alerts), abuse_data = await asyncio.gather(
        _load_threatintel_data(),
        _fetch_abuseipdb(query),
    )

    matched_wazuh = [
        a for a in wazuh_alerts
        if (a.get("data", {}).get("src_ip") == query or a.get("data", {}).get("dest_ip") == query)
    ]
    matched_ai = [a for a in ai_alerts if a.get("src_ip") == query]

    # Nếu không có dữ liệu nội bộ VÀ không có AbuseIPDB → 404
    if not matched_wazuh and not matched_ai and not abuse_data:
        raise HTTPException(status_code=404, detail=f"Không có dữ liệu threat intel cho: {query}")

    fired_sum = 0
    max_level = 1
    categories: list[str] = []
    latest_ts = datetime.fromtimestamp(0, tz=timezone.utc)
    country = "Unknown"

    for item in matched_wazuh:
        rule = item.get("rule", {})
        data = item.get("data", {})
        geo = item.get("GeoLocation", {})
        max_level = max(max_level, int(rule.get("level", 1) or 1))
        fired_sum += int(rule.get("firedtimes", 1) or 1)

        signature = str(data.get("alert", {}).get("signature") or "").strip()
        description = str(rule.get("description") or "").strip()
        if signature:
            categories.append(signature)
        elif description:
            categories.append(description)

        if not country or country == "Unknown":
            country = str(geo.get("country_name") or "Unknown")

        latest_ts = max(latest_ts, _parse_ts(item.get("@timestamp")))

    for item in matched_ai:
        latest_ts = max(latest_ts, _parse_ts(item.get("@timestamp")))

    # ── Tích hợp AbuseIPDB ──────────────────────────────────────────
    if abuse_data:
        abuse_score   = int(abuse_data.get("abuseConfidenceScore", 0))
        total_reports = int(abuse_data.get("totalReports", 0))
        isp           = str(abuse_data.get("isp") or abuse_data.get("domain") or "Unknown")
        usage_type    = str(abuse_data.get("usageType") or "Unknown")
        is_tor        = bool(abuse_data.get("isTor", False))
        is_vpn        = usage_type in ("VPN Service", "Hosting/Data Center", "Content Delivery Network")
        if abuse_data.get("countryName") and country == "Unknown":
            country = str(abuse_data["countryName"])
        if abuse_data.get("countryCode"):
            country_code = str(abuse_data["countryCode"])
        else:
            country_code = COUNTRY_CODE.get(country, "UN")
        # Ghép category từ AbuseIPDB reports
        for report in (abuse_data.get("reports") or [])[:10]:
            comment = str(report.get("comment") or "").strip()
            if comment and comment not in categories:
                categories.append(comment)
        # Nếu chưa có last_reported từ nội bộ, dùng AbuseIPDB
        if latest_ts == datetime.fromtimestamp(0, tz=timezone.utc):
            raw_last = abuse_data.get("lastReportedAt")
            if raw_last:
                latest_ts = _parse_ts(raw_last)
    else:
        # Fallback tính nội bộ khi không có AbuseIPDB
        total_reports = max(len(matched_wazuh), fired_sum)
        abuse_score   = min(100, int((total_reports * 0.7) + (max_level * 4)))
        isp           = "AS-Unknown"
        usage_type    = "Data Center" if abuse_score >= 50 else "Residential"
        is_tor        = False
        is_vpn        = False
        country_code  = COUNTRY_CODE.get(country, "UN")
    # ────────────────────────────────────────────────────────────────

    model_labels: list[str] = []
    for ai_item in matched_ai:
        for model in ai_item.get("triggered_models", []) or []:
            model_labels.append(MODEL_LABELS.get(model, model))

    categories = _dedupe_keep_order(categories)[:5]
    model_labels = _dedupe_keep_order(model_labels)[:4]
    country = country or "Unknown"

    return {
        "ip": query,
        "abuse_score": abuse_score,
        "country": country,
        "country_code": country_code,
        "isp": isp,
        "usage_type": usage_type,
        "is_tor": is_tor,
        "is_vpn": is_vpn,
        "categories": categories if categories else ["Hoạt động đáng ngờ"],
        "last_reported": latest_ts.isoformat().replace("+00:00", "Z"),
        "total_reports": total_reports,
        "so_canh_bao_wazuh": len(matched_wazuh),
        "mo_hinh_ai": model_labels,
        "nguon_abuseipdb": abuse_data is not None,
    }


@router.get("/iocs")
async def ioc_list(limit: int = Query(100, ge=1, le=500)):
    wazuh_alerts, _ = await _load_threatintel_data()

    grouped: dict[str, dict] = defaultdict(lambda: {
        "count": 0,
        "max_level": 1,
        "last_seen": datetime.fromtimestamp(0, tz=timezone.utc),
        "description": "",
    })

    for item in wazuh_alerts:
        src_ip = str(item.get("data", {}).get("src_ip") or "").strip()
        if not src_ip:
            continue
        rule = item.get("rule", {})
        row = grouped[src_ip]
        row["count"] += 1
        row["max_level"] = max(row["max_level"], int(rule.get("level", 1) or 1))
        row["last_seen"] = max(row["last_seen"], _parse_ts(item.get("@timestamp")))
        if not row["description"]:
            row["description"] = str(rule.get("description") or "Dấu hiệu tấn công lặp lại")

    rows = []
    for idx, (ip, agg) in enumerate(sorted(grouped.items(), key=lambda kv: kv[1]["count"], reverse=True), start=1):
        level = int(agg["max_level"])
        if level >= 10:
            muc_do = "cao"
        elif level >= 5:
            muc_do = "trung_binh"
        else:
            muc_do = "thap"

        rows.append({
            "ioc_id": f"IOC-{idx:03d}",
            "loai": "ip",
            "gia_tri": ip,
            "muc_do": muc_do,
            "mo_ta": agg["description"],
            "nguon": "Wazuh + Suricata",
            "lan_cuoi": agg["last_seen"].isoformat().replace("+00:00", "Z"),
            "da_kich_hoat": agg["count"] >= 3,
        })

    return rows[:limit]


@router.get("/feeds")
async def feed_sources():
    s = get_settings()
    abuseipdb_ok = bool(s.abuseipdb_api_key)

    # Đếm IOC thật từ OpenSearch
    try:
        wazuh = await get_recent_alerts(size=1200, min_level=1)
        unique_ips = {str(a.get("data", {}).get("src_ip") or "").strip() for a in wazuh}
        unique_ips.discard("")
        wazuh_ioc_count = len(unique_ips)
    except Exception:
        wazuh_ioc_count = 0

    try:
        ai_alerts = await get_ai_anomaly_alerts(size=600)
        ai_ioc_count = len({str(a.get("src_ip") or "").strip() for a in ai_alerts} - {""})
    except Exception:
        ai_ioc_count = 0

    return [
        {
            "feed_id": "abuseipdb",
            "ten": "AbuseIPDB",
            "icon": "🛡",
            "mo_ta": "IP reputation database",
            "trang_thai": "ket_noi" if abuseipdb_ok else "ngat",
            "ioc_count": len(_ABUSEIPDB_CACHE) if abuseipdb_ok else 0,
            "cap_nhat": "Thời gian thực (cache 1h)" if abuseipdb_ok else "Chưa có API key",
        },
        {
            "feed_id": "wazuh_suricata",
            "ten": "Wazuh + Suricata",
            "icon": "⚡",
            "mo_ta": "IDS/HIDS alerts feed",
            "trang_thai": "ket_noi",
            "ioc_count": wazuh_ioc_count,
            "cap_nhat": "Tự động (mỗi 10s)",
        },
        {
            "feed_id": "ai_engine",
            "ten": "AI Engine",
            "icon": "🤖",
            "mo_ta": "Anomaly detection từ AI",
            "trang_thai": "ket_noi",
            "ioc_count": ai_ioc_count,
            "cap_nhat": "Tự động (mỗi 60s)",
        },
        {
            "feed_id": "virustotal",
            "ten": "VirusTotal",
            "icon": "🔬",
            "mo_ta": "File & URL scanner",
            "trang_thai": "ngat",
            "ioc_count": 0,
            "cap_nhat": "Chưa kết nối",
        },
    ]


@router.post("/sync/{feed_id}")
async def sync_feed(feed_id: str):
    """Kích hoạt đồng bộ lại dữ liệu từ feed source."""
    if feed_id == "abuseipdb":
        _ABUSEIPDB_CACHE.clear()
        return {"ok": True, "message": "Đã xóa cache AbuseIPDB, lần tra cứu tiếp sẽ lấy dữ liệu mới"}
    if feed_id in ("wazuh_suricata", "ai_engine"):
        return {"ok": True, "message": f"Feed {feed_id} tự đồng bộ liên tục, không cần sync thủ công"}
    return {"ok": False, "message": f"Feed '{feed_id}' chưa được hỗ trợ"}


async def _load_threatintel_data() -> tuple[list[dict], list[dict]]:
    try:
        wazuh_alerts = await get_recent_alerts(size=1200, min_level=1)
    except Exception:
        wazuh_alerts = []

    try:
        ai_alerts = await get_ai_anomaly_alerts(size=600)
    except Exception:
        ai_alerts = []

    return wazuh_alerts, ai_alerts

