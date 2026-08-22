"""
REST API endpoints for triggering and inspecting openSquat brand scans.
"""

import json
import logging
import os
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import BaseModel, Field

from config import settings
from db import get_db, AsyncSessionLocal
from models import ScanRecord, DomainThreat, Case
from schemas import (
    ScanDetailResponse,
    ScanTriggerRequest,
    ScanTriggerResponse,
    DomainThreatItem,
    AntigravityRiskEventPayload,
)
from services.opensquat_runner import OpenSquatRunner
from services.antigravity_client import AntigravityClient
from tasks.process_domains import DomainThreatProcessor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


async def _run_scan_background(scan_id: str, brands: List[str], confidence_threshold: float):
    """
    Background worker function for asynchronous scan execution.
    """
    runner = OpenSquatRunner()
    processor = DomainThreatProcessor()

    async with AsyncSessionLocal() as session:
        try:
            # 1. Run openSquat
            scan_out = runner.execute_scan(
                brands=brands,
                confidence_threshold=confidence_threshold,
                scan_id=scan_id
            )

            # Update scan record with file path
            stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
            res = await session.execute(stmt)
            scan = res.scalars().first()
            if scan:
                scan.output_file = scan_out["filepath"]
                await session.commit()

            # 2. Ingest and analyze
            if settings.AUTO_TRIGGER_ANALYSIS:
                await processor.ingest_and_process_scan(
                    session=session,
                    scan_id=scan_id,
                    threats_data=scan_out["results"],
                )
                await session.commit()

            logger.info("Background scan %s completed successfully", scan_id)
        except Exception as e:
            logger.exception("Error in background scan %s: %s", scan_id, e)
            stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
            res = await session.execute(stmt)
            scan = res.scalars().first()
            if scan:
                scan.status = "FAILED"
                scan.error_message = str(e)
                await session.commit()


@router.post(
    "/domains",
    response_model=ScanTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an openSquat brand scan",
    description="Trigger an immediate openSquat lookalike domain scan for given brand list or default configured list.",
)
async def trigger_domain_scan(
    request: Optional[ScanTriggerRequest] = None,
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
):
    target_brands = (
        request.brand_list
        if request and request.brand_list
        else (settings.BRAND_LIST if isinstance(settings.BRAND_LIST, list) else ["google", "paypal", "microsoft"])
    )
    confidence = request.confidence_threshold if request else 0.70

    # Create Scan Record
    scan = ScanRecord(
        brand_list=target_brands,
        status="RUNNING",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch to background task or execute immediately
    if background_tasks:
        background_tasks.add_task(_run_scan_background, scan.id, target_brands, confidence)
    else:
        await _run_scan_background(scan.id, target_brands, confidence)

    return ScanTriggerResponse(
        scan_id=scan.id,
        status="RUNNING",
        brand_list=target_brands,
        message=f"Brand scan queued for {len(target_brands)} brands. Analysis in progress.",
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan execution details and raw results",
    description="Returns metadata and raw openSquat threat findings for a specific scan ID.",
)
async def get_scan_details(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
    res = await db.execute(stmt)
    scan = res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    # Load raw threats from disk if available, or from database threats relationship
    raw_results = []
    if scan.output_file and os.path.exists(scan.output_file):
        try:
            with open(scan.output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_results = [
                    DomainThreatItem(
                        domain=t["domain"],
                        brand=t["brand"],
                        similarity_score=t["similarity_score"],
                        registration_date=t.get("registration_date"),
                        vt_reputation=t.get("vt_reputation"),
                    )
                    for t in data.get("threats", [])
                ]
        except Exception as e:
            logger.warning("Could not read output file %s: %s", scan.output_file, e)

    # Fallback to database threats
    if not raw_results:
        threat_stmt = select(DomainThreat).where(DomainThreat.scan_id == scan.id)
        t_res = await db.execute(threat_stmt)
        threats = t_res.scalars().all()
        raw_results = [
            DomainThreatItem(
                domain=t.domain,
                brand=t.brand,
                similarity_score=t.similarity_score,
                registration_date=t.registration_date,
                vt_reputation=t.vt_reputation,
            )
            for t in threats
        ]

    return ScanDetailResponse(
        id=scan.id,
        brand_list=scan.brand_list,
        status=scan.status,
        results_count=scan.results_count or len(raw_results),
        output_file=scan.output_file,
        error_message=scan.error_message,
        created_at=scan.created_at,
        raw_results=raw_results,
    )


@router.get(
    "",
    response_model=List[ScanDetailResponse],
    summary="List all scan history",
    description="Retrieve a list of past brand scan runs.",
)
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanRecord).order_by(desc(ScanRecord.created_at)).offset(offset).limit(limit)
    res = await db.execute(stmt)
    scans = res.scalars().all()
    return scans


class InspectUrlRequest(BaseModel):
    url: str = Field(description="Target URL or domain to inspect for brand impersonation and threat signals")


@router.post(
    "/inspect-url",
    summary="Inspect a single URL immediately",
    description=(
        "Runs the full 9-stage modular analysis pipeline: official domain check, brand detection, "
        "typosquat classification, content/intent analysis, credential form detection, risk engine "
        "(with explicit risk reducers), Threat DNA fingerprinting, and campaign linking."
    ),
)
async def inspect_single_url(
    req: InspectUrlRequest,
    db: AsyncSession = Depends(get_db),
):
    from services.pipeline.orchestrator import run_pipeline

    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Run the full modular pipeline
    result = await run_pipeline(url=raw_url, db=db)

    # Save / update Case in DB with all pipeline fields
    case_stmt = select(Case).where(Case.target == result.target_url)
    case_res = await db.execute(case_stmt)
    case = case_res.scalars().first()

    antigravity_event_id = None

    if not case:
        case = Case(
            channel="web_domain",
            target=result.target_url,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            reasons=result.reasons,
            evidence=result.evidence,
            analysis_complete=result.analysis_complete,
            threat_dna=result.threat_dna,
            campaign_id=result.campaign_id,
            mutation_class=result.mutation_class,
            intent_class=result.intent_class,
        )
        db.add(case)
        await db.commit()
        await db.refresh(case)
    else:
        case.risk_score = result.risk_score
        case.risk_level = result.risk_level
        case.reasons = result.reasons
        case.evidence = result.evidence
        case.analysis_complete = result.analysis_complete
        case.threat_dna = result.threat_dna
        case.campaign_id = result.campaign_id
        case.mutation_class = result.mutation_class
        case.intent_class = result.intent_class
        await db.commit()
        await db.refresh(case)

    # Dispatch to Antigravity only when analysis is complete and above threshold
    if (
        result.analysis_complete
        and result.risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY
        and not case.antigravity_event_id
    ):
        ag_client = AntigravityClient()
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
        ag_res = await ag_client.send_risk_event(event_payload)
        case.antigravity_event_id = ag_res.get("event_id")
        await db.commit()
        await db.refresh(case)

    return {
        # Core fields (preserved for backward compatibility)
        "id": case.id,
        "target": result.target_url,
        "domain": result.domain,
        "brand_detected": result.brand_detected,
        "similarity_score": result.similarity_score,
        "trust_score": result.trust_score,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "reasons": result.reasons,
        "evidence": result.evidence,
        "analysis_complete": result.analysis_complete,
        "antigravity_event_id": case.antigravity_event_id,
        # Pipeline enrichment fields
        "pipeline_stages": result.pipeline_stages,
        "signals": result.signals,
        "risk_reducers": result.risk_reducers,
        "threat_dna": result.threat_dna,
        "campaign_id": result.campaign_id,
        "campaign_hits": result.campaign_hits,
        "mutation_class": result.mutation_class,
        "intent_class": result.intent_class,
        "is_official": result.is_official,
        "is_news": result.is_news,
    }
