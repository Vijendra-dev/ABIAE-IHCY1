"""
Pydantic schemas for request validation and response serialization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field, HttpUrl, ConfigDict


# ---------------------------------------------------------------------------
# Common / Generic
# ---------------------------------------------------------------------------
class HealthCheckResponse(BaseModel):
    status: str = "ok"
    app_name: str
    version: str
    timestamp: datetime


# ---------------------------------------------------------------------------
# openSquat & Scan Schemas
# ---------------------------------------------------------------------------
class ScanTriggerRequest(BaseModel):
    brand_list: Optional[List[str]] = Field(
        default=None,
        description="Optional override list of brand names to scan. If omitted, default configured BRAND_LIST is used.",
        examples=[["google", "paypal", "microsoft"]]
    )
    confidence_threshold: Optional[float] = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Minimum Levenshtein similarity threshold (0.0 to 1.0)",
    )


class DomainThreatItem(BaseModel):
    domain: str
    brand: str
    similarity_score: float
    registration_date: Optional[str] = None
    vt_reputation: Optional[Dict[str, Any]] = None


class ScanTriggerResponse(BaseModel):
    scan_id: str
    status: str
    brand_list: List[str]
    message: str


class ScanDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    brand_list: List[str]
    status: str
    results_count: int
    output_file: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    raw_results: Optional[List[DomainThreatItem]] = None


# ---------------------------------------------------------------------------
# Domain Threat Schemas
# ---------------------------------------------------------------------------
class DomainThreatResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: Optional[str] = None
    domain: str
    brand: str
    similarity_score: float
    registration_date: Optional[str] = None
    vt_reputation: Optional[Dict[str, Any]] = None
    status: str
    trustlens_score: Optional[float] = None
    trustlens_reasons: Optional[Any] = None
    created_at: datetime


# ---------------------------------------------------------------------------
# TrustLens-AI Integration Schemas
# ---------------------------------------------------------------------------
class TrustLensAnalyzeRequest(BaseModel):
    url: str = Field(description="Target URL to inspect with explainable multi-engine analysis")


class TrustLensEngineResult(BaseModel):
    ssl_valid: Optional[bool] = None
    dns_resolved: Optional[bool] = None
    mx_record_present: Optional[bool] = None
    content_impersonation_detected: Optional[bool] = None
    suspicious_form_detected: Optional[bool] = None
    page_title: Optional[str] = None
    ip_address: Optional[str] = None
    hosting_provider: Optional[str] = None
    whois_registrar: Optional[str] = None


class TrustLensAnalyzeResponse(BaseModel):
    trustScore: Optional[float] = Field(default=None, description="0 to 100 trust score (None if service unavailable)")
    riskLevel: str = Field(default="UNKNOWN", description="LOW, MEDIUM, HIGH, or UNKNOWN")
    reasons: List[str] = Field(default_factory=list, description="Human readable explainable security reasons")
    engines: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Engine specific telemetry")
    screenshot_url: Optional[str] = Field(default=None, description="Visual screenshot evidence URL")
    html_snapshot_url: Optional[str] = Field(default=None, description="Captured DOM snapshot URL")
    success: bool = Field(default=True, description="Whether analysis succeeded with live engine")
    fallback: bool = Field(default=False, description="Whether fallback analysis was used")


# ---------------------------------------------------------------------------
# Case Schemas
# ---------------------------------------------------------------------------
class CaseEvidence(BaseModel):
    screenshot_url: Optional[str] = None
    html_snapshot_url: Optional[str] = None
    whois: Optional[Dict[str, Any]] = None
    ssl: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    engines: Optional[Dict[str, Any]] = None
    raw_squat_data: Optional[Dict[str, Any]] = None


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    threat_id: Optional[str] = None
    channel: str
    target: str
    risk_score: int
    risk_level: str
    reasons: List[str]
    evidence: Dict[str, Any]
    analysis_complete: bool = True
    antigravity_event_id: Optional[str] = None
    created_at: datetime


class CaseListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CaseResponse]


# ---------------------------------------------------------------------------
# Antigravity Event Schemas
# ---------------------------------------------------------------------------
class AntigravityRiskEventPayload(BaseModel):
    event_type: str = "brand_impersonation_detected"
    case_id: str
    channel: str = "web_domain"
    target: str
    risk_score: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
    reasons: List[str]
    evidence: Dict[str, Any]
    recommended_action: str = "takedown_phishing"


class AntigravityRiskEventResponse(BaseModel):
    success: bool
    event_id: str
    status: str = "received"
    message: Optional[str] = None
