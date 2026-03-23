from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from services.cases import (
    create_case, get_case, list_cases,
    update_case_status, submit_triage,
    get_triage_log, case_stats
)

router = APIRouter(prefix="/api/cases", tags=["cases"])

class CaseCreate(BaseModel):
    title: str
    severity: str = "Medium"
    src_ip: str = ""
    agent: str = ""
    rule_id: str = ""
    rule_desc: str = ""
    mitre_ids: list[str] = []

class StatusUpdate(BaseModel):
    status: str
    assignee: str = ""

class TriageSubmit(BaseModel):
    classification: str          # True Positive / False Positive / Benign / Undetermined
    reasons: list[str] = []
    mitre_mapping: list[str] = []
    impact_level: str = "Medium"
    analysis: str = ""
    recommendation: str = ""
    analyst: str = "analyst"

@router.get("/stats")
def get_stats():
    return case_stats()

@router.get("/open")
def get_open_cases(limit: int = Query(10, ge=1, le=50)):
    """Chỉ trả về cases chưa đóng (New + In Progress + Escalated)
    — dùng cho panel 'Vụ việc đang mở' trên dashboard."""
    from services.cases import _conn, _row_to_dict
    with _conn() as c:
        rows = c.execute("""
            SELECT * FROM cases
            WHERE status IN ('New', 'In Progress', 'Escalated')
            ORDER BY
              CASE status
                WHEN 'Escalated'   THEN 1
                WHEN 'In Progress' THEN 2
                WHEN 'New'         THEN 3
              END,
              created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]

@router.get("/")
def get_cases(status: str = None, limit: int = 50):
    return list_cases(status=status, limit=limit)

@router.post("/")
def new_case(body: CaseCreate):
    return create_case(**body.dict())

@router.get("/{case_id}")
def get_one(case_id: str):
    c = get_case(case_id)
    if not c: raise HTTPException(404, "Case not found")
    return c

@router.patch("/{case_id}/status")
def patch_status(case_id: str, body: StatusUpdate):
    c = update_case_status(case_id, body.status, body.assignee or None)
    if not c: raise HTTPException(404, "Case not found")
    return c

@router.post("/{case_id}/triage")
def triage(case_id: str, body: TriageSubmit):
    if not get_case(case_id): raise HTTPException(404, "Case not found")
    return submit_triage(case_id, **body.dict())

@router.get("/{case_id}/triage")
def triage_log(case_id: str):
    return get_triage_log(case_id)

@router.post("/from-alert")
def case_from_alert(body: CaseCreate):
    """Create a case directly from a Wazuh alert (called by dashboard)."""
    return create_case(**body.dict())
