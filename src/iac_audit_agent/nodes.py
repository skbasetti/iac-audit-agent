from __future__ import annotations

import uuid
from pathlib import Path

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage

from .parsers import parse_cloudformation_file, parse_terraform_dir
from .state import (
    AgentState,
    ComplianceFindings,
    CostFindings,
    Finding,
    SecurityFindings,
)


def _llm() -> ChatAnthropic:
    return ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)


# ── Parser node ───────────────────────────────────────────────────────────────

def parser_node(state: AgentState) -> dict:
    path = Path(state["iac_path"])

    if not path.exists():
        return {"error": f"Path not found: {path}"}

    tf_files = (
        sorted(path.glob("**/*.tf"))
        if path.is_dir()
        else ([path] if path.suffix == ".tf" else [])
    )
    cf_candidates = (
        sorted(path.glob("**/*.yaml"))
        + sorted(path.glob("**/*.yml"))
        + sorted(path.glob("**/*.json"))
        if path.is_dir()
        else ([path] if path.suffix in {".yaml", ".yml", ".json"} else [])
    )

    if tf_files:
        iac_type = "terraform"
        resources, raw_content = parse_terraform_dir(tf_files)
    elif cf_candidates:
        iac_type = "cloudformation"
        resources, raw_content = parse_cloudformation_file(cf_candidates[0])
    else:
        return {
            "error": "No supported IaC files found (.tf / .yaml / .yml / .json)",
            "iac_type": "unknown",
            "resources": [],
            "raw_content": "",
        }

    return {"iac_type": iac_type, "resources": resources, "raw_content": raw_content}


# ── Security audit node ───────────────────────────────────────────────────────

_SECURITY_PROMPT = """\
You are a senior cloud security engineer auditing Infrastructure-as-Code.

Analyse the {iac_type} configuration below and return ONLY findings that are
genuinely present in the code. Do not hallucinate issues that are not there.

Check for:
- Security groups open to 0.0.0.0/0 on sensitive ports (22, 3389, 3306, 5432, 27017)
- S3 buckets with public access not fully blocked
- Unencrypted storage: EBS, RDS (storage_encrypted=false), S3 without SSE
- Overly permissive IAM (Action:"*", Resource:"*", AdministratorAccess)
- Hardcoded passwords, secrets, or access keys in resource config
- Publicly accessible RDS instances (publicly_accessible=true)
- Missing access logging on S3, ALB, CloudTrail
- EC2 instances missing IMDSv2 enforcement
- Missing deletion protection or backup retention on databases

Reference the EXACT resource name and attribute for every finding.

IaC content:
{content}"""


def security_audit_node(state: AgentState) -> dict:
    if not state.get("resources"):
        return {"security_findings": []}

    structured = _llm().with_structured_output(SecurityFindings)
    result: SecurityFindings = structured.invoke(
        [HumanMessage(content=_SECURITY_PROMPT.format(
            iac_type=state["iac_type"],
            content=state["raw_content"][:8000],
        ))]
    )
    for f in result.findings:
        f.category = "security"
    return {"security_findings": result.findings}


# ── Compliance check node ─────────────────────────────────────────────────────

_COMPLIANCE_PROMPT = """\
You are a cloud compliance expert auditing Infrastructure-as-Code.

Analyse the {iac_type} configuration against:
- CIS AWS Foundations Benchmark v1.5
- SOC 2 Type II (CC6, CC7, A1 controls)
- NIST CSF (Identify, Protect, Detect)

Check for:
- Missing CloudTrail with log file validation enabled
- No VPC flow logs on VPCs
- CloudWatch alarms not set for root login / unauthorized API calls
- S3 buckets missing MFA delete on versioned buckets
- No deletion protection on critical databases (SOC 2 availability)
- Missing automated backups (backup_retention_period = 0)
- Resources without mandatory tags (asset management — SOC 2 CC6.1)
- Encryption in transit not enforced
- No GuardDuty or Security Hub defined

Map each finding to the framework control it violates.
Reference EXACT resource names from the configuration.

IaC content:
{content}"""


def compliance_check_node(state: AgentState) -> dict:
    if not state.get("resources"):
        return {"compliance_findings": []}

    structured = _llm().with_structured_output(ComplianceFindings)
    result: ComplianceFindings = structured.invoke(
        [HumanMessage(content=_COMPLIANCE_PROMPT.format(
            iac_type=state["iac_type"],
            content=state["raw_content"][:8000],
        ))]
    )
    for f in result.findings:
        f.category = "compliance"
    return {"compliance_findings": result.findings}


# ── Cost analysis node ────────────────────────────────────────────────────────

_COST_PROMPT = """\
You are a FinOps engineer auditing Infrastructure-as-Code for cost waste.

Analyse the {iac_type} configuration and identify:
- Oversized instance types
- GP2 EBS volumes that should migrate to GP3 (30% cheaper)
- NAT Gateways replaceable with VPC endpoints for S3/DynamoDB
- Oversized RDS instances
- Missing S3 lifecycle policies
- Unattached or unused Elastic IPs
- Multi-AZ enabled on non-production environments

Estimate monthly USD savings per finding where possible.
Reference exact resource names. Do not invent issues not present in the config.

IaC content:
{content}"""


def cost_analysis_node(state: AgentState) -> dict:
    if not state.get("resources"):
        return {"cost_findings": [], "cost_savings_estimate": 0.0}

    structured = _llm().with_structured_output(CostFindings)
    result: CostFindings = structured.invoke(
        [HumanMessage(content=_COST_PROMPT.format(
            iac_type=state["iac_type"],
            content=state["raw_content"][:8000],
        ))]
    )
    for f in result.findings:
        f.category = "cost"
    return {"cost_findings": result.findings, "cost_savings_estimate": result.estimated_monthly_savings_usd}


# ── Synthesizer node ──────────────────────────────────────────────────────────

_SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def _as_finding(f) -> Finding:
    return Finding(**f) if isinstance(f, dict) else f


def synthesizer_node(state: AgentState) -> dict:
    all_findings: list[Finding] = [
        _as_finding(f)
        for f in (
            state.get("security_findings", [])
            + state.get("compliance_findings", [])
            + state.get("cost_findings", [])
        )
    ]

    if not all_findings:
        return {"all_findings": [], "severity_score": 0.0, "requires_human_review": False}

    total_weight = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in all_findings)
    max_possible = len(all_findings) * 10
    severity_score = round((total_weight / max_possible) * 10, 2)

    has_critical = any(f.severity == "CRITICAL" for f in all_findings)
    high_count = sum(1 for f in all_findings if f.severity == "HIGH")
    requires_human_review = has_critical or severity_score >= 8.0 or high_count >= 5

    return {
        "all_findings": all_findings,
        "severity_score": severity_score,
        "requires_human_review": requires_human_review,
    }


# ── Human review node ─────────────────────────────────────────────────────────

def human_review_node(state: AgentState) -> dict:
    decision = state.get("human_decision", "approve")
    if decision == "reject":
        return {"error": "Audit report rejected by human reviewer. Pipeline halted."}
    return {}


# ── Report generator node ─────────────────────────────────────────────────────

def report_generator_node(state: AgentState) -> dict:
    findings = state.get("all_findings", [])
    severity_counts: dict[str, int] = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in findings:
        severity_counts[f.severity] += 1

    report = {
        "run_id": f"aud_{uuid.uuid4().hex[:12]}",
        "iac_path": state["iac_path"],
        "iac_type": state["iac_type"],
        "severity_score": state.get("severity_score", 0.0),
        "human_reviewed": state.get("human_decision") is not None,
        "human_decision": state.get("human_decision"),
        "summary": {
            **severity_counts,
            "total": len(findings),
            "cost_savings_estimate_usd_monthly": round(state.get("cost_savings_estimate", 0.0), 2),
        },
        "findings": [f.model_dump() for f in findings],
    }
    return {"report": report}
