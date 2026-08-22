"""
Modular Analysis Pipeline Package.

Stages:
  1. official_check      — verify if domain is a known official domain
  2. brand_detector      — Levenshtein brand matching
  3. typosquat_classifier — mutation class detection
  4. content_analyzer    — TrustLens engine signal extraction
  5. risk_engine         — weighted scoring with explicit risk reducers
  6. threat_dna          — compact fingerprint generation
  7. campaign_linker     — DB look-up for matching threat DNA

Entry point: orchestrator.run_pipeline(url, db) -> PipelineResult
"""

from .orchestrator import run_pipeline, PipelineResult

__all__ = ["run_pipeline", "PipelineResult"]
