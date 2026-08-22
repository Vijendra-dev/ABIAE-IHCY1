"""
Stage 8 — Campaign Linker.

Queries the cases table for existing cases with matching threat_dna.
If ≥ 2 cases share the same DNA, they are considered part of a campaign.
Returns the deterministic campaign_id and hit count.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from .threat_dna import campaign_id_from_dna

CAMPAIGN_MIN_HITS = 2   # minimum matching cases to form a campaign


@dataclass
class CampaignResult:
    threat_dna: str
    campaign_id: Optional[str]   # None if below threshold
    campaign_hits: int            # total cases sharing this DNA


async def run(
    db: AsyncSession,
    threat_dna: str,
    exclude_case_id: Optional[str] = None,
) -> CampaignResult:
    """
    Look up how many cases share *threat_dna*.

    Parameters
    ----------
    db              : async DB session
    threat_dna      : the fingerprint string from Stage 7
    exclude_case_id : case ID to exclude from the count (the current case)

    Returns
    -------
    CampaignResult
    """
    # Import here to avoid circular imports at module level
    from models import Case

    try:
        stmt = select(func.count(Case.id)).where(Case.threat_dna == threat_dna)
        if exclude_case_id:
            stmt = stmt.where(Case.id != exclude_case_id)

        result = await db.execute(stmt)
        hits = result.scalar() or 0
    except Exception:
        # DB column may not exist on first boot before migration; safe fallback
        hits = 0

    cid: Optional[str] = None
    if hits >= CAMPAIGN_MIN_HITS:
        cid = campaign_id_from_dna(threat_dna)

    return CampaignResult(
        threat_dna=threat_dna,
        campaign_id=cid,
        campaign_hits=int(hits),
    )
