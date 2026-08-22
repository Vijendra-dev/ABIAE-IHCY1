"""
Stage 7 — Threat DNA.

Builds a compact, deterministic fingerprint for a threat case.
Format: {mutation_class}:{brand}:{intent_class}:{risk_tier}

Examples:
  phishing_keyword:paypal:credential_harvest:HIGH
  homoglyph:google:phishing:CRITICAL
  official:paypal:benign:LOW
  unrelated:unknown:unknown:UNKNOWN
"""

from __future__ import annotations

import hashlib


def build(
    mutation_class: str,
    brand: str,
    intent_class: str,
    risk_level: str,
) -> str:
    """
    Build a Threat DNA string.

    All components are normalised to lowercase.
    Unknown/empty values are replaced with 'unknown'.
    """
    mc = (mutation_class or "unrelated").lower().strip()
    b = (brand or "unknown").lower().strip()
    ic = (intent_class or "unknown").lower().strip()
    rl = (risk_level or "unknown").lower().strip()
    return f"{mc}:{b}:{ic}:{rl}"


def campaign_id_from_dna(dna: str) -> str:
    """
    Deterministic campaign ID derived from Threat DNA.
    Format: camp_{first 8 hex chars of sha256(dna)}
    """
    digest = hashlib.sha256(dna.encode()).hexdigest()[:8]
    return f"camp_{digest}"
