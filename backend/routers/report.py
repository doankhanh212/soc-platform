from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse
import asyncio

from services import get_recent_alerts, get_suricata_alerts, get_ai_anomaly_alerts
from services.html_generator import normalize_findings, generate_security_report_html


router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/security-intelligence", response_class=HTMLResponse)
async def security_intelligence_report(
    target: str = Query("AI-SOC Platform"),
    scan_type: str = Query("SIEM + IDS + AI Behavioral Analysis"),
    methodology: str = Query("Wazuh + Suricata + AI anomaly scoring + analyst triage model"),
    version: str = Query("AI-SOC-SEC-REPORT v2.0"),
    hours: int = Query(24, ge=1, le=168),
):
    # Current data services are 24h-centric; keeping the param for API contract.
    _ = hours

    wazuh, suricata, ai_alerts = await asyncio.gather(
        get_recent_alerts(size=500, min_level=1),
        get_suricata_alerts(size=300),
        get_ai_anomaly_alerts(size=200),
        return_exceptions=True,
    )
    if isinstance(wazuh, Exception):
        wazuh = []
    if isinstance(suricata, Exception):
        suricata = []
    if isinstance(ai_alerts, Exception):
        ai_alerts = []

    findings = normalize_findings(wazuh, suricata, ai_alerts)
    html_doc = generate_security_report_html(
        findings,
        meta={
            "target": target,
            "scan_type": scan_type,
            "methodology": methodology,
            "version": version,
        },
    )
    return HTMLResponse(content=html_doc)
