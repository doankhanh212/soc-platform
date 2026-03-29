"""
OpenSearch service — field mapping verified against real Wazuh 4.x data.

Real field structure from wazuh-alerts-4.x-*:
  Suricata alerts:
    data.src_ip, data.dest_ip, data.src_port, data.dest_port
    data.alert.signature, data.alert.severity, data.alert.signature_id
    data.proto, data.event_type, data.in_iface
    data.flow.bytes_toserver, data.flow.pkts_toserver
  GeoLocation: GeoLocation.latitude, GeoLocation.longitude,
               GeoLocation.country_name, GeoLocation.city_name
  Agent: agent.name, agent.ip, agent.id
  Rule:  rule.id, rule.level, rule.description, rule.groups, rule.firedtimes
         rule.mitre.id, rule.mitre.tactic  (on HIDS alerts)
"""
import logging

import httpx
from config import get_settings

cfg = get_settings()
log = logging.getLogger(__name__)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=cfg.opensearch_url,
        auth=(cfg.opensearch_user, cfg.opensearch_password),
        verify=cfg.opensearch_verify_ssl,
        timeout=15.0,
    )


async def _search(index: str, body: dict) -> dict:
    async with _client() as c:
        r = await c.post(f"/{index}/_search", json=body)
        r.raise_for_status()
        return r.json()


async def _index_document(index: str, body: dict) -> None:
    async with _client() as c:
        r = await c.post(f"/{index}/_doc", json=body)
        r.raise_for_status()


# ─── ALERTS ───────────────────────────────────────────────────────

async def get_recent_alerts(size: int = 100, min_level: int = 1) -> list[dict]:
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
        "_source": [
            "@timestamp", "timestamp",
            "agent.name", "agent.ip", "agent.id",
            "rule.id", "rule.level", "rule.description",
            "rule.groups", "rule.firedtimes",
            "rule.mitre.id", "rule.mitre.tactic",
            "data.src_ip", "data.dest_ip",
            "data.src_port", "data.dest_port",
            "data.proto", "data.event_type",
            "data.alert.signature", "data.alert.severity",
            "data.alert.signature_id",
            "GeoLocation.country_name", "GeoLocation.city_name",
            "GeoLocation.latitude", "GeoLocation.longitude",
            "location", "full_log",
        ],
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


async def get_suricata_alerts(size: int = 100) -> list[dict]:
    """Suricata alerts: agent.name='Suricata', rule.groups contains 'suricata'"""
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"exists": {"field": "data.alert.signature"}},
                ]
            }
        },
        "_source": [
            "@timestamp",
            "data.src_ip", "data.dest_ip",
            "data.src_port", "data.dest_port",
            "data.alert.signature", "data.alert.severity",
            "data.alert.signature_id",
            "data.proto", "data.event_type", "data.in_iface",
            "data.flow.bytes_toserver", "data.flow.pkts_toserver",
            "GeoLocation.country_name", "GeoLocation.city_name",
            "GeoLocation.latitude", "GeoLocation.longitude",
            "rule.level", "rule.description", "rule.firedtimes",
        ],
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


async def get_ai_anomaly_alerts(size: int = 50) -> list[dict]:
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
    }
    try:
        result = await _search(cfg.index_ai_anomaly, body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []


# ─── STATS ────────────────────────────────────────────────────────

async def get_dashboard_kpis() -> dict:
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "total":          {"value_count": {"field": "@timestamp"}},
            "critical":       {"filter": {"range": {"rule.level": {"gte": 12}}}},
            "high":           {"filter": {"range": {"rule.level": {"gte": 7, "lte": 11}}}},
            # Count unique attacking IPs from Suricata (data.src_ip)
            "unique_src_ips": {"cardinality": {"field": "data.src_ip"}},
            # Also count by suricata vs wazuh
            "suricata_alerts":{"filter": {"exists": {"field": "data.alert.signature"}}},
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    aggs = result["aggregations"]
    return {
        "total_alerts_24h":  aggs["total"]["value"],
        "critical_alerts":   aggs["critical"]["doc_count"],
        "high_alerts":       aggs["high"]["doc_count"],
        "unique_attackers":  aggs["unique_src_ips"]["value"],
        "suricata_alerts":   aggs["suricata_alerts"]["doc_count"],
    }


async def get_top_attacking_ips(size: int = 10) -> list[dict]:
    """Use data.src_ip (Suricata field) as primary attack source."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "top_ips": {
                "terms": {"field": "data.src_ip", "size": size}
            }
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    buckets = result["aggregations"]["top_ips"]["buckets"]
    return [
        {"ip": b["key"], "count": b["doc_count"]}
        for b in buckets
        if b["key"] not in ("", "127.0.0.1", "::1", "0.0.0.0")
    ]


async def get_top_ips_with_geo(size: int = 12) -> list[dict]:
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "by_srcip": {
                "terms": {
                    "field": "data.srcip",
                    "size": size
                },
                "aggs": {
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["GeoLocation"]
                        }
                    }
                }
            },
            "by_src_ip": {
                "terms": {
                    "field": "data.src_ip",
                    "size": size
                },
                "aggs": {
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["GeoLocation"]
                        }
                    }
                }
            }
        }
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    aggs = result.get("aggregations", {})
    seen: dict = {}

    def _merge_bucket(bucket: dict) -> None:
        ip = bucket["key"]
        if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return
        hits = bucket.get("geo", {}).get("hits", {}).get("hits", [])
        geo = hits[0]["_source"].get("GeoLocation", {}) if hits else {}
        loc = geo.get("location", {})
        current = seen.get(ip, {
            "ip": ip,
            "count": 0,
            "country": "",
            "city": "",
            "lat": 0.0,
            "lon": 0.0,
        })
        current["count"] += bucket["doc_count"]
        if geo:
            current["country"] = current["country"] or geo.get("country_name", "")
            current["city"] = current["city"] or geo.get("city_name", "")
            current["lat"] = current["lat"] or float(loc.get("lat", 0) or 0)
            current["lon"] = current["lon"] or float(loc.get("lon", 0) or 0)
        seen[ip] = current

    for b in aggs.get("by_srcip", {}).get("buckets", []):
        _merge_bucket(b)
    for b in aggs.get("by_src_ip", {}).get("buckets", []):
        _merge_bucket(b)

    return sorted(seen.values(),
                  key=lambda x: x["count"],
                  reverse=True)[:size]


async def index_ai_anomaly_alert(result: dict) -> None:
    doc = {
        "@timestamp": result.get("timestamp"),
        "src_ip": result.get("src_ip", ""),
        "risk_score": result.get("risk_score", 0.0),
        "risk_level": result.get("risk_level", "LOW"),
        "anomaly_score": result.get("anomaly_score", 0.0),
        "triggered_models": result.get("triggered_models", []),
        "model_scores": result.get("model_scores", {}),
        "risk_components": result.get("risk_components", {}),
        "features": result.get("features", {}),
        "alerts_1h": result.get("alerts_1h", 0),
        "should_block": result.get("should_block", False),
        "da_chan": result.get("da_chan", False),
        "auto_block_reason": result.get("auto_block_reason", ""),
        "explanation": result.get("explanation", {}),
    }
    try:
        await _index_document(cfg.index_ai_anomaly, doc)
    except Exception as e:
        log.warning("AI anomaly index write failed: %s", e)


async def get_alerts_over_time(hours: int = 24) -> list[dict]:
    interval = "30m" if hours <= 24 else ("2h" if hours <= 72 else "6h")
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"},
                }
            }
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in result["aggregations"]["over_time"]["buckets"]
    ]


async def get_mitre_stats() -> dict:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-7d"}}},
                    {"exists": {"field": "rule.mitre.id"}},
                ]
            }
        },
        "aggs": {
            "techniques": {"terms": {"field": "rule.mitre.id",     "size": 50}},
            "tactics":    {"terms": {"field": "rule.mitre.tactic", "size": 20}},
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    aggs = result["aggregations"]
    return {
        "techniques": [{"id": b["key"], "count": b["doc_count"]} for b in aggs["techniques"]["buckets"]],
        "tactics":    [{"name": b["key"], "count": b["doc_count"]} for b in aggs["tactics"]["buckets"]],
    }


async def get_alert_severity_breakdown() -> dict:
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {"by_level": {"terms": {"field": "rule.level", "size": 20}}},
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return {str(b["key"]): b["doc_count"]
            for b in result["aggregations"]["by_level"]["buckets"]}


async def get_top_rules(size: int = 8) -> list[dict]:
    """Top fired rules by count — for bar chart."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.description", "size": size}
            }
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return [
        {"rule": b["key"], "count": b["doc_count"]}
        for b in result["aggregations"]["top_rules"]["buckets"]
    ]


async def get_suricata_signature_stats() -> list[dict]:
    """Top Suricata signatures for bar chart."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"exists": {"field": "data.alert.signature"}},
                ]
            }
        },
        "aggs": {
            "top_sigs": {"terms": {"field": "data.alert.signature", "size": 10}}
        },
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    return [
        {"signature": b["key"], "count": b["doc_count"]}
        for b in result["aggregations"]["top_sigs"]["buckets"]
    ]
