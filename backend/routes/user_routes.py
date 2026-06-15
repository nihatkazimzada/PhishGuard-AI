from collections import Counter
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import ScanResult, User

router = APIRouter(prefix="/api/user", tags=["user"])


class SettingsOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    created_at: str
    api_calls_count: int


class SettingsIn(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: EmailStr


@router.get("/settings", response_model=SettingsOut)
def get_settings(current_user: User = Depends(get_current_user)):
    return SettingsOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        created_at=current_user.created_at.isoformat(),
        api_calls_count=current_user.api_calls_count or 0,
    )


@router.put("/settings", response_model=SettingsOut)
def update_settings(
    payload: SettingsIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conflict = (
        db.query(User)
        .filter(
            User.id != current_user.id,
            ((User.email == payload.email) | (User.username == payload.username)),
        )
        .first()
    )
    if conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another account already uses that email or username.",
        )

    current_user.email = payload.email
    current_user.username = payload.username
    db.commit()
    db.refresh(current_user)

    return SettingsOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        created_at=current_user.created_at.isoformat(),
        api_calls_count=current_user.api_calls_count or 0,
    )


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = db.query(ScanResult).filter(ScanResult.user_id == current_user.id).all()
    total = len(scans)
    verdict_counts = Counter(s.verdict for s in scans)
    phishing = verdict_counts.get("PHISHING", 0)
    suspicious = verdict_counts.get("SUSPICIOUS", 0)
    safe = verdict_counts.get("SAFE", 0)

    now = datetime.utcnow()
    this_month_count = sum(
        1
        for s in scans
        if s.scanned_at.year == now.year and s.scanned_at.month == now.month
    )

    monthly_buckets = [0] * 12
    for s in scans:
        if s.scanned_at.year == now.year:
            monthly_buckets[s.scanned_at.month - 1] += 1

    return {
        "total_scans": total,
        "phishing_caught": phishing,
        "suspicious_flagged": suspicious,
        "safe_emails": safe,
        "this_month": this_month_count,
        "monthly_breakdown": monthly_buckets,
        "verdict_distribution": {
            "PHISHING": phishing,
            "SUSPICIOUS": suspicious,
            "SAFE": safe,
        },
    }
