"""
Domain Threat Ingestion and Processing Pipeline.
Ingests openSquat findings, runs the modular analysis pipeline per domain,
persists Case records with Threat DNA + campaign linking, and routes
qualifying alerts to Antigravity.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import DomainThreat, Case, ScanRecord
from schemas import AntigravityRiskEventPayload
from services.antigravity_client import AntigravityClient
from services.pipeline.orchestrator import run_pipeline

logger = logging.getLogger(__name__)


class DomainThreatProcessor:
    """
    Orchestrates the lifecycle of detected brand lookalike domains:
    openSquat → DomainThreat → Pipeline (brand, typosquat, content, risk, DNA, campaign) → Case → Antigravity.
    """

    def __init__(
        self,
        antigravity_client: Optional[AntigravityClient] = None,
    ):
        self.antigravity_client = antigravity_client or AntigravityClient()

    async def ingest_and_process_scan(
        self,
        session: AsyncSession,
        scan_id: str,
        threats_data: List[Dict[str, Any]],
    ) -> List[Case]:
        """
        Processes a batch of openSquat threats for a given scan run.
        Runs the full 9-stage pipeline per domain.
        """
        created_cases: List[Case] = []

        logger.info("Processing %d detected domains for scan_id=%s", len(threats_data), scan_id)

        for threat_item in threats_data:
            domain = threat_item.get("domain", "").strip().lower()
            brand = threat_item.get("brand", "").strip().lower()
            similarity_score = float(threat_item.get("similarity_score", 0.0))
            registration_date = threat_item.get("registration_date")

            if not domain:
                continue

            target_url = f"https://{domain}"

            # 1. Persist / update DomainThreat record
            stmt = select(DomainThreat).where(DomainThreat.domain == domain)
            res = await session.execute(stmt)
            threat = res.scalars().first()

            if not threat:
                threat = DomainThreat(
                    scan_id=scan_id,
                    domain=domain,
                    brand=brand,
                    similarity_score=similarity_score,
                    registration_date=registration_date,
                    vt_reputation=threat_item.get("vt_reputation", {}),
                    status="PENDING_ANALYSIS",
                )
                session.add(threat)
                await session.flush()
            else:
                threat.similarity_score = max(threat.similarity_score, similarity_score)
                threat.scan_id = scan_id
                threat.status = "PENDING_ANALYSIS"
                await session.flush()

            # 2. Run full modular analysis pipeline
            threat.status = "ANALYZING"
            await session.flush()

            try:
                result = await run_pipeline(url=target_url, db=session)
                threat.trustlens_score = result.trust_score
                threat.trustlens_reasons = result.reasons
                threat.status = "ANALYZED" if result.analysis_complete else "TRUSTLENS_UNAVAILABLE"
            except Exception as e:
                logger.error("Pipeline error for %s: %s", target_url, e)
                threat.status = "FAILED"
                await session.flush()
                continue

            await session.flush()

            # 3. Create or update Case record with all pipeline fields
            case_stmt = select(Case).where(Case.target == target_url)
            case_res = await session.execute(case_stmt)
            case = case_res.scalars().first()

            if not case:
                case = Case(
                    threat_id=threat.id,
                    channel="web_domain",
                    target=target_url,
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
                session.add(case)
                await session.flush()
            else:
                case.risk_score = result.risk_score
                case.risk_level = result.risk_level
                case.reasons = result.reasons
                case.evidence = result.evidence
                case.analysis_complete = result.analysis_complete
                case.threat_id = threat.id
                case.threat_dna = result.threat_dna
                case.campaign_id = result.campaign_id
                case.mutation_class = result.mutation_class
                case.intent_class = result.intent_class
                await session.flush()

            # 4. Dispatch to Antigravity only when analysis is complete and above threshold
            if (
                result.analysis_complete
                and result.risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY
                and not case.antigravity_event_id
            ):
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
                ag_res = await self.antigravity_client.send_risk_event(event_payload)
                case.antigravity_event_id = ag_res.get("event_id")
                await session.flush()

            created_cases.append(case)

        # Update scan record summary
        scan_stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
        s_res = await session.execute(scan_stmt)
        scan_rec = s_res.scalars().first()
        if scan_rec:
            scan_rec.status = "COMPLETED"
            scan_rec.results_count = len(created_cases)
            await session.flush()

        logger.info("Successfully ingested scan %s with %d total cases", scan_id, len(created_cases))
        return created_cases

    async def process_file(self, session: AsyncSession, filepath: str) -> List[Case]:
        """
        Reads an openSquat output JSON file and processes all contained threats.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        scan_id = data.get("scan_id")
        threats = data.get("threats", [])
        return await self.ingest_and_process_scan(session, scan_id=scan_id, threats_data=threats)
