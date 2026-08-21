"""
Domain Threat Ingestion and Processing Pipeline.
Ingests openSquat findings, executes TrustLens-AI analysis, computes unified risk,
persists Case records, and routes qualifying alerts to Antigravity.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import DomainThreat, Case, ScanRecord
from schemas import AntigravityRiskEventPayload
from services.trustlens_client import TrustLensClient
from services.scoring import RiskScorer
from services.antigravity_client import AntigravityClient

logger = logging.getLogger(__name__)


class DomainThreatProcessor:
    """
    Orchestrates the lifecycle of detected brand lookalike domains:
    openSquat -> DomainThreat (PENDING_ANALYSIS) -> TrustLens -> Case -> Antigravity.
    """

    def __init__(
        self,
        trustlens_client: Optional[TrustLensClient] = None,
        antigravity_client: Optional[AntigravityClient] = None,
    ):
        self.trustlens_client = trustlens_client or TrustLensClient()
        self.antigravity_client = antigravity_client or AntigravityClient()

    async def ingest_and_process_scan(
        self,
        session: AsyncSession,
        scan_id: str,
        threats_data: List[Dict[str, Any]],
    ) -> List[Case]:
        """
        Processes a batch of openSquat threats for a given scan run.
        """
        created_cases: List[Case] = []

        logger.info("Processing %d detected domains for scan_id=%s", len(threats_data), scan_id)

        for threat_item in threats_data:
            domain = threat_item.get("domain", "").strip().lower()
            brand = threat_item.get("brand", "").strip().lower()
            similarity_score = float(threat_item.get("similarity_score", 0.0))
            registration_date = threat_item.get("registration_date")
            vt_reputation = threat_item.get("vt_reputation", {})

            if not domain or not brand:
                continue

            # 1. Check if DomainThreat already exists
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
                    vt_reputation=vt_reputation,
                    status="PENDING_ANALYSIS",
                )
                session.add(threat)
                await session.flush()
            else:
                threat.similarity_score = max(threat.similarity_score, similarity_score)
                threat.scan_id = scan_id
                threat.status = "PENDING_ANALYSIS"
                await session.flush()

            # 2. Analyze URL with TrustLens-AI
            target_url = f"https://{domain}"
            threat.status = "ANALYZING"
            await session.flush()

            try:
                trustlens_result = await self.trustlens_client.analyze_url(target_url)
                trust_score = trustlens_result.get("trustScore", 50.0)
                trust_reasons = trustlens_result.get("reasons", [])
                engine_details = trustlens_result.get("engines", {})

                threat.trustlens_score = trust_score
                threat.trustlens_reasons = trust_reasons
                threat.status = "ANALYZED"
            except Exception as e:
                logger.error("Error analyzing %s with TrustLens-AI: %s", target_url, e)
                threat.status = "FAILED"
                trust_score = 30.0  # Conservative estimate
                trust_reasons = [f"TrustLens automated analysis failed: {str(e)}"]
                engine_details = {}
                trustlens_result = {
                    "trustScore": trust_score,
                    "reasons": trust_reasons,
                    "engines": {},
                }

            await session.flush()

            # 3. Calculate Combined Case Risk Score & Reasons
            risk_score, risk_level = RiskScorer.calculate_combined_risk(
                similarity_score=similarity_score,
                trustlens_score=trust_score,
                vt_reputation=vt_reputation,
                engine_details=engine_details,
            )

            combined_reasons = RiskScorer.aggregate_reasons(
                brand=brand,
                domain=domain,
                similarity_score=similarity_score,
                trustlens_reasons=trust_reasons,
                vt_reputation=vt_reputation,
                engine_details=engine_details,
            )

            evidence_obj = RiskScorer.build_evidence_package(
                domain=domain,
                brand=brand,
                similarity_score=similarity_score,
                registration_date=registration_date,
                vt_reputation=vt_reputation,
                trustlens_data=trustlens_result,
            )

            # 4. Create or Update Case Record
            case_stmt = select(Case).where(Case.target == target_url)
            case_res = await session.execute(case_stmt)
            case = case_res.scalars().first()

            if not case:
                case = Case(
                    threat_id=threat.id,
                    channel="web_domain",
                    target=target_url,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    reasons=combined_reasons,
                    evidence=evidence_obj,
                )
                session.add(case)
                await session.flush()
            else:
                case.risk_score = risk_score
                case.risk_level = risk_level
                case.reasons = combined_reasons
                case.evidence = evidence_obj
                case.threat_id = threat.id
                await session.flush()

            # 5. Dispatch to Antigravity if above configured risk threshold
            if risk_score >= settings.RISK_THRESHOLD_FOR_ANTIGRAVITY and not case.antigravity_event_id:
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
