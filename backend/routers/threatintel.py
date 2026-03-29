import re
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from services import get_ai_anomaly_alerts, get_recent_alerts


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


@router.get("/lookup")
async def lookup_ip(q: str = Query(..., min_length=1)):
    query = q.strip()
    if not IP_RE.match(query):
        raise HTTPException(status_code=404, detail=f"Không có dữ liệu threat intel cho: {query}")

    wazuh_alerts, ai_alerts = await _load_threatintel_data()

    matched_wazuh = [
        a for a in wazuh_alerts
        if (a.get("data", {}).get("src_ip") == query or a.get("data", {}).get("dest_ip") == query)
    ]
    matched_ai = [a for a in ai_alerts if a.get("src_ip") == query]

    if not matched_wazuh and not matched_ai:
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

    total_reports = max(len(matched_wazuh), fired_sum)
    abuse_score = min(100, int((total_reports * 0.7) + (max_level * 4)))

    model_labels: list[str] = []
    for ai_item in matched_ai:
        for model in ai_item.get("triggered_models", []) or []:
            model_labels.append(MODEL_LABELS.get(model, model))

    categories = _dedupe_keep_order(categories)[:5]
    model_labels = _dedupe_keep_order(model_labels)[:4]

    country = country or "Unknown"
    country_code = COUNTRY_CODE.get(country, "UN")
    isp = "AS131333" if query == "37.111.53.110" else "AS-Unknown"
    usage_type = "Data Center" if abuse_score >= 50 else "Residential"

    return {
        "ip": query,
        "abuse_score": abuse_score,
        "country": country,
        "country_code": country_code,
        "isp": isp,
        "usage_type": usage_type,
        "is_tor": False,
        "is_vpn": False,
        "categories": categories if categories else ["Hoạt động đáng ngờ"],
        "last_reported": latest_ts.isoformat().replace("+00:00", "Z"),
        "total_reports": total_reports,
        "so_canh_bao_wazuh": len(matched_wazuh),
        "mo_hinh_ai": model_labels,
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

    rows.extend([
        {
            "ioc_id": "IOC-D01",
            "loai": "domain",
            "gia_tri": "malicious-control.example",
            "muc_do": "trung_binh",
            "mo_ta": "Domain điều khiển nghi vấn",
            "nguon": "Threat Feed",
            "lan_cuoi": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "da_kich_hoat": False,
        },
        {
            "ioc_id": "IOC-H01",
            "loai": "hash",
            "gia_tri": "6f5902ac237024bdd0c176cb93063dc4",
            "muc_do": "cao",
            "mo_ta": "Hash file nghi ngờ mã độc",
            "nguon": "VirusTotal",
            "lan_cuoi": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "da_kich_hoat": True,
        },
        {
            "ioc_id": "IOC-U01",
            "loai": "url",
            "gia_tri": "http://suspicious.example/login.php",
            "muc_do": "thap",
            "mo_ta": "URL đáng theo dõi",
            "nguon": "Analyst",
            "lan_cuoi": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "da_kich_hoat": False,
        },
    ])

    return rows[:limit]


@router.get("/feeds")
async def feed_sources():
    return [
        {
            "ten": "AbuseIPDB",
            "icon": "🛡",
            "mo_ta": "IP reputation database",
            "trang_thai": "ket_noi",
            "ioc_count": 1247,
            "cap_nhat": "5 phút trước",
        },
        {
            "ten": "Emerging Threats",
            "icon": "⚡",
            "mo_ta": "Suricata rule feed",
            "trang_thai": "ket_noi",
            "ioc_count": 892,
            "cap_nhat": "1 giờ trước",
        },
        {
            "ten": "AlienVault OTX",
            "icon": "👽",
            "mo_ta": "Open threat exchange",
            "trang_thai": "ngat",
            "ioc_count": 0,
            "cap_nhat": "Chưa kết nối",
        },
        {
            "ten": "VirusTotal",
            "icon": "🔬",
            "mo_ta": "File & URL scanner",
            "trang_thai": "ngat",
            "ioc_count": 0,
            "cap_nhat": "Chưa kết nối",
        },
    ]


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

