from __future__ import annotations

import operator
import uuid
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:6].upper()}")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: Literal["security", "compliance", "cost"]
    resource: str
    resource_type: str
    rule: str
    message: str
    remediation: str


class SecurityFindings(BaseModel):
    findings: list[Finding]
    summary: str = ""


class ComplianceFindings(BaseModel):
    findings: list[Finding]
    frameworks_checked: list[str] = Field(default_factory=list)
    summary: str = ""


class CostFindings(BaseModel):
    findings: list[Finding]
    estimated_monthly_savings_usd: float = 0.0
    summary: str = ""


class AgentState(TypedDict):
    # Input
    iac_path: str
    iac_type: str
    raw_content: str
    resources: list[dict]

    # Parallel node outputs — operator.add reducer merges results from Send branches
    security_findings: Annotated[list[Finding], operator.add]
    compliance_findings: Annotated[list[Finding], operator.add]
    cost_findings: Annotated[list[Finding], operator.add]
    cost_savings_estimate: Annotated[float, operator.add]

    # Synthesised
    all_findings: list[Finding]
    severity_score: float
    requires_human_review: bool

    # Human checkpoint (written by CLI before resuming)
    human_decision: Optional[str]
    human_notes: Optional[str]

    # Final
    report: Optional[dict]
    error: Optional[str]
