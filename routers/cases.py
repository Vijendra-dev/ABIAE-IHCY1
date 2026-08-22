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
from models import Case
from schemas import (
    CaseListResponse,
    CaseResponse,
    AntigravityRiskEventPayload,
)
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
        description="Filter by risk level category: LOW, MEDIUM, HIGH, or CRITICAL"
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
        description="Search substring in target URL"
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
    description="Fetch a detailed brand threat case dossier including explainable reasons, Threat DNA, and campaign context.",
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
    summary="Re-evaluate case with full modular pipeline",
    description=(
        "Manually re-triggers the full 9-stage analysis pipeline for the target URL, "
        "recalculates risk score with explicit risk reducers, updates Threat DNA and campaign "
        "linking, and dispatches to Antigravity if above threshold."
    ),
)
async def reevaluate_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
):
    from services.pipeline.orchestrator import run_pipeline

    stmt = select(Case).where(Case.id == case_id)
    res = await db.execute(stmt)
    case = res.scalars().first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found",
        )

    # Run full pipeline on the case target URL
    result = await run_pipeline(url=case.target, db=db, existing_case_id=case_id)

    # Update case with all pipeline outputs
    case.risk_score = result.risk_score
    case.risk_level = result.risk_level
    case.reasons = result.reasons
    case.evidence = result.evidence
    case.analysis_complete = result.analysis_complete
    case.threat_dna = result.threat_dna
    case.campaign_id = result.campaign_id
    case.mutation_class = result.mutation_class
    case.intent_class = result.intent_class

    # Antigravity dispatch if warranted
    if (
        result.analysis_complete
        and result.risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY
    ):
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
