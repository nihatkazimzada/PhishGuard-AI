from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.ai_engine import analyze_email
from backend.auth import get_current_user
from backend.database import get_db
from backend.models import ScanResult, User

router = APIRouter(prefix="/api/scan", tags=["scan"])


class ScanIn(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1, max_length=20000)


class ScanOut(BaseModel):
    id: int
    email_subject: str | None
    email_body: str
    risk_score: int
    verdict: str
    ai_explanation: str | None
    indicators: dict
    scanned_at: str


def _scan_to_out(scan: ScanResult) -> ScanOut:
    return ScanOut(
        id=scan.id,
        email_subject=scan.email_subject,
        email_body=scan.email_body,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        ai_explanation=scan.ai_explanation,
        indicators=scan.indicators or {},
        scanned_at=scan.scanned_at.isoformat(),
    )


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = analyze_email(payload.subject, payload.body)

    verdict = result.get("verdict", "SUSPICIOUS")
    risk_score = int(result.get("risk_score", 0) or 0)
    explanation_parts = [result.get("summary", "")]
    if result.get("recommendation"):
        explanation_parts.append(f"Recommendation: {result['recommendation']}")
    if result.get("technical_details"):
        explanation_parts.append(f"Technical: {result['technical_details']}")
    if result.get("error"):
        explanation_parts.append("(Analysis service temporarily unavailable.)")
    if result.get("fallback"):
        explanation_parts.append("(Heuristic fallback was used.)")

    scan = ScanResult(
        user_id=current_user.id,
        email_subject=payload.subject or None,
        email_body=payload.body,
        risk_score=risk_score,
        verdict=verdict,
        ai_explanation="\n\n".join([p for p in explanation_parts if p]),
        indicators=result.get("indicators") or {},
    )

    current_user.api_calls_count = (current_user.api_calls_count or 0) + 1
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _scan_to_out(scan)


@router.get("/history", response_model=dict)
def scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base_query = db.query(ScanResult).filter(ScanResult.user_id == current_user.id)
    total = base_query.count()
    items = (
        base_query.order_by(ScanResult.scanned_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [_scan_to_out(scan).model_dump() for scan in items],
    }


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = (
        db.query(ScanResult)
        .filter(ScanResult.id == scan_id, ScanResult.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return _scan_to_out(scan)
