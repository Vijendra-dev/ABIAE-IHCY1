"""
REST API endpoints for querying, filtering, and inspecting Security Cases.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import get_db
from models import Case, DomainThreat
from schemas import (
    CaseListResponse,
    CaseResponse,
    AntigravityRiskEventPayload,
)
from services.trustlens_client import TrustLensClient
from services.scoring import RiskScorer
from services.antigravity_client import AntigravityClient

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List all brand risk cases",
    description="Retrieve a paginated list of brand security cases with optional filtering by risk level, channel, and minimum score.",
)
async def list_cases(
    risk_level: Optional[str] = Query(
        None,
        description="Filter by risk level category: LOW, MEDIUM, or HIGH"
    ),
    channel: Optional[str] = Query(
        None,
        description="Filter by detection channel (default: web_domain)"
    ),
    min_score: Optional[int] = Query(
        None,
        ge=0,
        le=100,
        description="Filter for cases with risk_score >= min_score"
    ),
    search: Optional[str] = Query(
        None,
        description="Search substring in target URL or reasons"
    ),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
):
    query = select(Case)

    if risk_level:
        query = query.where(Case.risk_level == risk_level.upper())
    if channel:
        query = query.where(Case.channel == channel)
    if min_score is not None:
        query = query.where(Case.risk_score >= min_score)
    if search:
        search_pattern = f"%{search}%"
        query = query.where(Case.target.ilike(search_pattern))

    # Total count
    count_stmt = select(func.count()).select_from(query.subquery())
    count_res = await db.execute(count_stmt)
    total = count_res.scalar_one()

    # Paginated results
    offset = (page - 1) * page_size
    paged_query = query.order_by(desc(Case.risk_score), desc(Case.created_at)).offset(offset).limit(page_size)
    items_res = await db.execute(paged_query)
    cases = items_res.scalars().all()

    return CaseListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=cases,
    )


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Get case details and evidence",
    description="Fetch a detailed brand threat case dossier including visual screenshot, DOM snapshot, SSL/DNS telemetry, and explainable reasons.",
)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Case).where(Case.id == case_id)
    res = await db.execute(stmt)
    case = res.scalars().first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found",
        )

    return case


@router.post(
    "/{case_id}/re-evaluate",
    response_model=CaseResponse,
    summary="Re-evaluate case with TrustLens and sync to Antigravity",
    description="Manually re-triggers TrustLens-AI inspection for the target URL, recalculates risk score, and dispatches to Antigravity if above threshold.",
)
async def reevaluate_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Case).where(Case.id == case_id)
    res = await db.execute(stmt)
    case = res.scalars().first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found",
        )

    # Get linked DomainThreat if present
    similarity_score = 0.8
    brand = "Unknown"
    registration_date = None
    vt_reputation = {}

    if case.threat_id:
        t_stmt = select(DomainThreat).where(DomainThreat.id == case.threat_id)
        t_res = await db.execute(t_stmt)
        threat = t_res.scalars().first()
        if threat:
            similarity_score = threat.similarity_score
            brand = threat.brand
            registration_date = threat.registration_date
            vt_reputation = threat.vt_reputation or {}

    # Call TrustLens
    trustlens_client = TrustLensClient()
    trustlens_res = await trustlens_client.analyze_url(case.target)
    is_available = bool(trustlens_res.get("success", False)) and not bool(trustlens_res.get("fallback", False))

    trust_score = trustlens_res.get("trustScore")
    trust_reasons = trustlens_res.get("reasons", [])
    engine_details = trustlens_res.get("engines", {})

    # Re-calculate
    new_risk_score, new_risk_level = RiskScorer.calculate_combined_risk(
        similarity_score=similarity_score,
        trustlens_score=trust_score,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
        trustlens_available=is_available,
    )

    combined_reasons = RiskScorer.aggregate_reasons(
        brand=brand,
        domain=case.target.replace("https://", "").replace("http://", ""),
        similarity_score=similarity_score,
        trustlens_reasons=trust_reasons,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
        trustlens_available=is_available,
    )

    evidence_obj = RiskScorer.build_evidence_package(
        domain=case.target.replace("https://", "").replace("http://", ""),
        brand=brand,
        similarity_score=similarity_score,
        registration_date=registration_date or "N/A",
        vt_reputation=vt_reputation,
        trustlens_data=trustlens_res,
    )

    case.risk_score = new_risk_score
    case.risk_level = new_risk_level
    case.reasons = combined_reasons
    case.evidence = evidence_obj
    case.analysis_complete = is_available

    # Check Antigravity dispatch only if analysis is complete and meets threshold
    if is_available and new_risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY:
        antigravity_client = AntigravityClient()
        event_payload = AntigravityRiskEventPayload(
            case_id=case.id,
            channel=case.channel,
            target=case.target,
            risk_score=case.risk_score,
            risk_level=case.risk_level,
            reasons=case.reasons,
            evidence=case.evidence,
            recommended_action="takedown_phishing",
        )
        ag_res = await antigravity_client.send_risk_event(event_payload)
        case.antigravity_event_id = ag_res.get("event_id")

    await db.commit()
    await db.refresh(case)
    return case
