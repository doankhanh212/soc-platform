"""
API để xem và quản lý detection rules từ dashboard.
Cho phép analyst xem rules đang active, tạo case thủ công từ alert.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from services.cases import create_case
from services.rule_engine import AUTO_RULES, run_once

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("/")
async def list_rules():
    """Trả về danh sách rules đang active."""
    return [
        {"name": r["name"], "severity": r["severity"], "active": True}
        for r in AUTO_RULES
    ]


@router.post("/run-now")
async def trigger_now():
    """Chạy rule engine ngay lập tức (không cần chờ 60s)."""
    await run_once()
    return {"status": "ok", "message": "Rule engine executed"}


class BulkCaseCreate(BaseModel):
    alerts: list[dict]  # list alert objects từ frontend


@router.post("/bulk-create-cases")
async def bulk_create(body: BulkCaseCreate):
    """
    Tạo cases hàng loạt từ danh sách alerts
    (dùng cho medium/low alerts mà analyst chọn tay).
    """
    created = []
    for alert in body.alerts:
        level = int(alert.get("rule", {}).get("level", 0))
        sev = ("Critical" if level >= 12 else
               "High"     if level >= 7  else
               "Medium"   if level >= 4  else "Low")
        mitre = alert.get("rule", {}).get("mitre", {})
        c = create_case(
            title=alert.get("rule", {}).get("description", "Manual case"),
            severity=sev,
            src_ip=alert.get("data", {}).get("src_ip", ""),
            agent=alert.get("agent", {}).get("name", ""),
            rule_id=str(alert.get("rule", {}).get("id", "")),
            rule_desc=alert.get("rule", {}).get("description", ""),
            mitre_ids=mitre.get("id", []),
        )
        created.append(c["case_id"])
    return {"created": len(created), "case_ids": created}
