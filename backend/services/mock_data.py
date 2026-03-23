import math
import random
from datetime import datetime, timedelta, timezone

UTC = timezone.utc

_ATTACKERS = [
    {"ip": "8.8.8.8", "lat": 37.3861, "lon": -122.0839, "country": "United States", "city": "Mountain View"},
    {"ip": "1.1.1.1", "lat": -33.8688, "lon": 151.2093, "country": "Australia", "city": "Sydney"},
    {"ip": "104.18.32.45", "lat": 37.7749, "lon": -122.4194, "country": "United States", "city": "San Francisco"},
    {"ip": "51.158.47.10", "lat": 48.8566, "lon": 2.3522, "country": "France", "city": "Paris"},
    {"ip": "95.163.121.77", "lat": 55.7558, "lon": 37.6173, "country": "Russia", "city": "Moscow"},
    {"ip": "123.125.114.144", "lat": 39.9042, "lon": 116.4074, "country": "China", "city": "Beijing"},
    {"ip": "81.2.69.160", "lat": 51.5072, "lon": -0.1276, "country": "United Kingdom", "city": "London"},
    {"ip": "91.198.174.192", "lat": 52.52, "lon": 13.405, "country": "Germany", "city": "Berlin"},
    {"ip": "103.244.90.10", "lat": 22.3193, "lon": 114.1694, "country": "Hong Kong", "city": "Hong Kong"},
    {"ip": "142.250.70.78", "lat": 43.6511, "lon": -79.347, "country": "Canada", "city": "Toronto"},
]

_SURICATA_SIGNATURES = [
    {"name": "ET SCAN Nmap SYN Scan", "severity": 2, "sid": 2100498},
    {"name": "ET SSH Brute Force Attempt", "severity": 1, "sid": 2024218},
    {"name": "ET EXPLOIT SMBv1 EternalBlue Attempt", "severity": 1, "sid": 2024219},
    {"name": "ET MALWARE Possible CnC Beacon", "severity": 2, "sid": 2030012},
]

_WAZUH_RULES = [
    {"id": "5710", "level": 10, "description": "sshd: authentication failed", "groups": ["authentication_failed", "sshd"]},
    {"id": "550", "level": 7, "description": "Integrity checksum changed", "groups": ["syscheck", "integrity"]},
    {"id": "31103", "level": 5, "description": "Possible SQL injection attempt", "groups": ["web", "attack"]},
    {"id": "60122", "level": 7, "description": "Privilege escalation attempt detected", "groups": ["pam", "privilege_escalation"]},
]

_MITRE_POOL = [
    ("T1110", "Credential Access"),
    ("T1078", "Persistence"),
    ("T1548", "Privilege Escalation"),
    ("T1190", "Initial Access"),
    ("T1059", "Execution"),
]


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _build_alert(i: int) -> dict:
    attacker = _ATTACKERS[i % len(_ATTACKERS)]
    sig = _SURICATA_SIGNATURES[i % len(_SURICATA_SIGNATURES)]
    rule = _WAZUH_RULES[i % len(_WAZUH_RULES)]
    mitre_a = _MITRE_POOL[i % len(_MITRE_POOL)]
    mitre_b = _MITRE_POOL[(i + 2) % len(_MITRE_POOL)]

    ts = _now() - timedelta(minutes=i * 6)
    src_port = random.choice([22, 80, 443, 3389, 445, 8080])
    dst_port = random.choice([22, 80, 443, 3389, 9200])

    return {
        "@timestamp": _iso(ts),
        "timestamp": _iso(ts),
        "agent": {
            "id": f"00{i % 7}",
            "name": f"srv-{(i % 5) + 1:02d}",
            "ip": f"10.10.0.{(i % 5) + 10}",
        },
        "rule": {
            "id": rule["id"],
            "level": rule["level"],
            "description": rule["description"],
            "groups": rule["groups"],
            "firedtimes": random.randint(2, 120),
            "mitre": {
                "id": [mitre_a[0], mitre_b[0]],
                "tactic": [mitre_a[1], mitre_b[1]],
            },
        },
        "data": {
            "src_ip": attacker["ip"],
            "dest_ip": f"10.0.0.{(i % 200) + 20}",
            "src_port": src_port,
            "dest_port": dst_port,
            "proto": random.choice(["TCP", "UDP"]),
            "in_iface": random.choice(["eth0", "ens160"]),
            "flow": {
                "bytes_toserver": random.randint(1200, 120000),
            },
            "alert": {
                "signature": sig["name"],
                "severity": sig["severity"],
                "signature_id": sig["sid"],
                "category": random.choice([
                    "Attempted Administrator Privilege Gain",
                    "Potentially Bad Traffic",
                    "Attempted Information Leak",
                    "Attempted Denial of Service",
                ]),
            },
        },
        "GeoLocation": {
            "latitude": attacker["lat"],
            "longitude": attacker["lon"],
            "country_name": attacker["country"],
            "city_name": attacker["city"],
        },
        "location": "suricata",
        "full_log": "Mock Wazuh 4.x event",
    }


def _dataset(size: int = 180) -> list[dict]:
    return [_build_alert(i) for i in range(size)]


async def get_recent_alerts(size: int = 100, min_level: int = 1) -> list[dict]:
    alerts = [a for a in _dataset(220) if (a.get("rule", {}).get("level", 0) >= min_level)]
    return alerts[:size]


async def get_suricata_alerts(size: int = 100) -> list[dict]:
    alerts = [a for a in _dataset(200) if a.get("data", {}).get("alert", {}).get("signature")]
    return alerts[:size]


async def get_ai_anomaly_alerts(size: int = 50) -> list[dict]:
    now = _now()
    items = []
    for i in range(size):
        attacker = _ATTACKERS[i % len(_ATTACKERS)]
        risk = round(0.35 + ((i * 13) % 55) / 100, 3)
        items.append({
            "@timestamp": _iso(now - timedelta(minutes=i * 13)),
            "src_ip": attacker["ip"],
            "risk_score": risk,
            "triggered_models": ["IsolationForest", "EWMA"] if i % 2 == 0 else ["CUSUM", "Entropy"],
            "should_block": risk >= 0.75,
        })
    return items


async def get_dashboard_kpis() -> dict:
    alerts = _dataset(220)
    src_ips = {a.get("data", {}).get("src_ip") for a in alerts if a.get("data", {}).get("src_ip")}
    critical = sum(1 for a in alerts if (a.get("rule", {}).get("level", 0) >= 12))
    high = sum(1 for a in alerts if (7 <= a.get("rule", {}).get("level", 0) <= 11))
    return {
        "total_alerts_24h": len(alerts),
        "critical_alerts": critical,
        "high_alerts": high,
        "unique_attackers": len(src_ips),
        "suricata_alerts": len(alerts),
    }


async def get_top_attacking_ips(size: int = 10) -> list[dict]:
    counts = {}
    for a in _dataset(220):
        ip = a.get("data", {}).get("src_ip")
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"ip": ip, "count": cnt} for ip, cnt in ranked[:size]]


async def get_top_ips_with_geo(size: int = 12) -> list[dict]:
    top = await get_top_attacking_ips(size=size)
    lookup = {a["ip"]: a for a in _ATTACKERS}
    rows = []
    for item in top:
        geo = lookup.get(item["ip"])
        if not geo:
            continue
        rows.append({
            "ip": item["ip"],
            "lat": geo["lat"],
            "lon": geo["lon"],
            "country": geo["country"],
            "city": geo["city"],
            "count": item["count"],
        })
    return rows


async def get_alerts_over_time(hours: int = 24) -> list[dict]:
    points = 48 if hours <= 24 else (36 if hours <= 72 else 28)
    step_hours = max(hours / points, 0.5)
    now = _now()

    center = points * 0.62
    sigma = max(points * 0.1, 1)

    rows = []
    for i in range(points):
        baseline = 7 + 3 * math.sin(i / 3.2)
        spike = 38 * math.exp(-((i - center) ** 2) / (2 * sigma * sigma))
        count = max(0, int(round(baseline + spike + random.uniform(-2.2, 2.2))))
        t = now - timedelta(hours=(points - i) * step_hours)
        rows.append({"time": _iso(t), "count": count})
    return rows


async def get_mitre_stats() -> dict:
    alerts = _dataset(180)
    tech = {}
    tactics = {}
    for a in alerts:
        mitre = a.get("rule", {}).get("mitre", {})
        for m in mitre.get("id", []):
            tech[m] = tech.get(m, 0) + 1
        for t in mitre.get("tactic", []):
            tactics[t] = tactics.get(t, 0) + 1

    techniques = [{"id": k, "count": v} for k, v in sorted(tech.items(), key=lambda x: x[1], reverse=True)[:50]]
    tactic_rows = [{"name": k, "count": v} for k, v in sorted(tactics.items(), key=lambda x: x[1], reverse=True)[:20]]
    return {"techniques": techniques, "tactics": tactic_rows}


async def get_alert_severity_breakdown() -> dict:
    levels = {}
    for a in _dataset(200):
        lvl = str(a.get("rule", {}).get("level", 0))
        levels[lvl] = levels.get(lvl, 0) + 1
    return levels


async def get_top_rules(size: int = 8) -> list[dict]:
    counts = {}
    for a in _dataset(220):
        rule = a.get("rule", {}).get("description")
        if not rule:
            continue
        counts[rule] = counts.get(rule, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"rule": rule, "count": cnt} for rule, cnt in ranked[:size]]


async def get_suricata_signature_stats() -> list[dict]:
    counts = {}
    for a in _dataset(220):
        sig = a.get("data", {}).get("alert", {}).get("signature")
        if not sig:
            continue
        counts[sig] = counts.get(sig, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"signature": sig, "count": cnt} for sig, cnt in ranked[:10]]
