from fastapi import APIRouter, Query
from services.opensearch import _search
from config import get_settings

router = APIRouter(prefix="/api/hunting", tags=["hunting"])
cfg = get_settings()

@router.get("/search")
async def hunt(
    q:        str   = Query("", description="Từ khóa tìm kiếm"),
    hours:    int   = Query(24, ge=1, le=720),
    agent:    str   = Query(""),
    src_ip:   str   = Query(""),
    rule_id:  str   = Query(""),
    min_level:int   = Query(1, ge=1, le=15),
    size:     int   = Query(100, ge=1, le=500),
):
    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if min_level > 1:
        must.append({"range": {"rule.level": {"gte": min_level}}})

    filters = []
    if agent:
        filters.append({"wildcard": {"agent.name": f"*{agent}*"}})
    if src_ip:
        filters.append({"bool": {"should": [
            {"wildcard": {"data.src_ip":  f"*{src_ip}*"}},
            {"wildcard": {"data.srcip":   f"*{src_ip}*"}},
            {"wildcard": {"agent.ip":     f"*{src_ip}*"}},
        ]}})
    if rule_id:
        filters.append({"term": {"rule.id": rule_id}})

    # Full-text search across key fields
    if q:
        filters.append({"bool": {"should": [
            {"wildcard": {"rule.description":  f"*{q}*"}},
            {"wildcard": {"data.src_ip":       f"*{q}*"}},
            {"wildcard": {"data.srcip":        f"*{q}*"}},
            {"wildcard": {"agent.name":        f"*{q}*"}},
            {"wildcard": {"rule.id":           f"*{q}*"}},
            {"match":    {"full_log":           q}},
        ], "minimum_should_match": 1}})

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must":   must,
                "filter": filters,
            }
        },
        "_source": [
            "@timestamp", "agent.name", "agent.ip",
            "rule.id", "rule.level", "rule.description",
            "rule.groups", "rule.mitre.id", "rule.mitre.tactic",
            "data.src_ip", "data.srcip", "data.dest_ip",
            "data.src_port", "data.dest_port", "data.proto",
            "data.alert.signature", "data.alert.severity",
            "GeoLocation.country_name",
            "full_log", "location",
        ],
    }

    result = await _search(cfg.index_wazuh_alerts, body)
    hits = result.get("hits", {})
    return {
        "total":   hits.get("total", {}).get("value", 0),
        "results": [h["_source"] for h in hits.get("hits", [])],
        "took_ms": result.get("took", 0),
    }

@router.get("/stats")
async def hunt_stats(
    q:      str = Query(""),
    hours:  int = Query(24),
):
    """Thống kê nhanh: top agents, top rules, top IPs cho query hiện tại."""
    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if q:
        must.append({"bool": {"should": [
            {"wildcard": {"rule.description": f"*{q}*"}},
            {"wildcard": {"data.src_ip":      f"*{q}*"}},
            {"wildcard": {"agent.name":       f"*{q}*"}},
        ], "minimum_should_match": 1}})

    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "top_agents": {"terms": {"field": "agent.name",       "size": 5}},
            "top_rules":  {"terms": {"field": "rule.description", "size": 5}},
            "top_src_ip": {"terms": {"field": "data.src_ip",      "size": 5}},
            "top_srcip":  {"terms": {"field": "data.srcip",       "size": 5}},
        }
    }
    result = await _search(cfg.index_wazuh_alerts, body)
    aggs = result.get("aggregations", {})
    
    # Merge 2 IP fields
    ip_map = {}
    for b in aggs.get("top_src_ip",{}).get("buckets",[]):
        ip_map[b["key"]] = ip_map.get(b["key"],0) + b["doc_count"]
    for b in aggs.get("top_srcip",{}).get("buckets",[]):
        ip_map[b["key"]] = ip_map.get(b["key"],0) + b["doc_count"]
    top_ips = sorted(
        [{"ip":k,"count":v} for k,v in ip_map.items()],
        key=lambda x: x["count"], reverse=True
    )[:5]

    return {
        "top_agents": [{"name":b["key"],"count":b["doc_count"]}
                       for b in aggs.get("top_agents",{}).get("buckets",[])],
        "top_rules":  [{"rule":b["key"],"count":b["doc_count"]}
                       for b in aggs.get("top_rules",{}).get("buckets",[])],
        "top_ips":    top_ips,
    }
