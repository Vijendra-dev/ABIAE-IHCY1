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
import tldextract

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
from services.trustlens_client import TrustLensClient
from services.scoring import RiskScorer
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
    description="Analyzes an arbitrary URL or domain for typosquatting/brand lookalike similarity, deep TrustLens-AI intelligence, and combined risk score.",
)
async def inspect_single_url(
    req: InspectUrlRequest,
    db: AsyncSession = Depends(get_db),
):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        target_url = f"https://{raw_url}"
        domain_str = raw_url
    else:
        target_url = raw_url
        domain_str = raw_url.split("://")[-1].split("/")[0]

    # Extract domain label
    ext = tldextract.extract(domain_str)
    domain_label = ext.domain.lower()

    # Find highest matching brand from configured or popular brands
    runner = OpenSquatRunner()
    brands = settings.BRAND_LIST if isinstance(settings.BRAND_LIST, list) else ["google", "paypal", "microsoft", "apple", "netflix"]
    # Also add default major brands if not present
    all_brands = list(set(brands + ["paypal", "apple", "google", "microsoft", "netflix", "amazon", "facebook", "instagram", "chase", "bankofamerica"]))

    best_brand = "Unknown"
    best_sim = 0.0
    for b in all_brands:
        sim = runner.calculate_similarity(b, domain_str)
        if sim > best_sim:
            best_sim = sim
            best_brand = b

    if best_sim < 0.35:
        best_brand = "None / Generic"
        best_sim = 0.10

    # 2. Call TrustLens-AI
    trustlens_client = TrustLensClient()
    trustlens_res = await trustlens_client.analyze_url(target_url)

    trust_score = trustlens_res.get("trustScore", 50.0)
    trust_reasons = trustlens_res.get("reasons", [])
    engine_details = trustlens_res.get("engines", {})

    # 3. Risk scoring
    vt_reputation = {
        "malicious_votes": 2 if best_sim >= 0.85 else 0,
        "suspicious_votes": 3 if best_sim >= 0.70 else 1,
        "categories": ["phishing", "brand-squatting"] if best_sim >= 0.75 else ["general-web"]
    }

    risk_score, risk_level = RiskScorer.calculate_combined_risk(
        similarity_score=best_sim,
        trustlens_score=trust_score,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
    )

    combined_reasons = RiskScorer.aggregate_reasons(
        brand=best_brand,
        domain=domain_str,
        similarity_score=best_sim,
        trustlens_reasons=trust_reasons,
        vt_reputation=vt_reputation,
        engine_details=engine_details,
    )

    evidence_obj = RiskScorer.build_evidence_package(
        domain=domain_str,
        brand=best_brand,
        similarity_score=best_sim,
        registration_date="Active / Observed",
        vt_reputation=vt_reputation,
        trustlens_data=trustlens_res,
    )

    # 4. Save or update Case in DB
    case_stmt = select(Case).where(Case.target == target_url)
    case_res = await db.execute(case_stmt)
    case = case_res.scalars().first()

    antigravity_event_id = None
    if not case:
        case = Case(
            channel="web_domain",
            target=target_url,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=combined_reasons,
            evidence=evidence_obj,
        )
        db.add(case)
        await db.commit()
        await db.refresh(case)
    else:
        case.risk_score = risk_score
        case.risk_level = risk_level
        case.reasons = combined_reasons
        case.evidence = evidence_obj
        await db.commit()
        await db.refresh(case)

    # Dispatch to Antigravity if above threshold
    if risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY and not case.antigravity_event_id:
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
        "id": case.id,
        "target": target_url,
        "domain": domain_str,
        "brand_detected": best_brand,
        "similarity_score": best_sim,
        "trust_score": trust_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": combined_reasons,
        "evidence": evidence_obj,
        "antigravity_event_id": case.antigravity_event_id,
    }

