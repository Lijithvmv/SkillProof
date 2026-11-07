"""Configurable assurance gates that prepare evidence for human approval."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    code: str
    severity: Literal["critical", "high", "medium", "low", "info"]


class AssurancePolicy(BaseModel):
    policy_id: str = Field(default="default", min_length=1, max_length=120)
    minimum_structural_score: float = Field(default=70, ge=0, le=100)
    minimum_instruction_quality_score: float = Field(default=60, ge=0, le=100)
    minimum_security_score: float = Field(default=70, ge=0, le=100)
    minimum_behavioral_lift_pp: float = Field(default=0, ge=-100, le=100)
    minimum_paired_runs: int = Field(default=3, ge=1, le=10000)
    minimum_models: int = Field(default=1, ge=1, le=100)
    maximum_cost_overhead_percent: float = Field(default=100, ge=0, le=10000)


class AssuranceInput(BaseModel):
    structural_score: float | None = Field(default=None, ge=0, le=100)
    instruction_quality_score: float | None = Field(default=None, ge=0, le=100)
    security_score: float | None = Field(default=None, ge=0, le=100)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    behavioral_lift_pp: float | None = Field(default=None, ge=-100, le=10000)
    paired_runs: int | None = Field(default=None, ge=0)
    measured_models: int | None = Field(default=None, ge=0)
    cost_overhead_percent: float | None = Field(default=None, ge=-100, le=100000)


def evaluate_assurance(evidence: AssuranceInput, policy: AssurancePolicy | None = None) -> dict[str, Any]:
    policy = policy or AssurancePolicy()
    gates: list[dict[str, str]] = []

    def score_gate(code: str, label: str, value: float | None, threshold: float) -> None:
        if value is None:
            gates.append({"code": code, "status": "insufficient_evidence", "message": f"{label} score was not provided."})
        elif value >= threshold:
            gates.append({"code": code, "status": "pass", "message": f"{label} score {value:.1f} meets minimum {threshold:.1f}."})
        else:
            gates.append({"code": code, "status": "fail", "message": f"{label} score {value:.1f} is below minimum {threshold:.1f}."})

    score_gate("STRUCTURAL_QUALITY", "Structural quality", evidence.structural_score, policy.minimum_structural_score)
    score_gate("INSTRUCTION_QUALITY", "Instruction quality", evidence.instruction_quality_score, policy.minimum_instruction_quality_score)
    score_gate("STATIC_SECURITY_SCORE", "Static security", evidence.security_score, policy.minimum_security_score)

    high_findings = [finding for finding in evidence.security_findings if finding.severity in {"critical", "high"}]
    medium_findings = [finding for finding in evidence.security_findings if finding.severity == "medium"]
    if high_findings:
        gates.append({"code": "HIGH_SECURITY_FINDINGS", "status": "blocked", "message": f"{len(high_findings)} critical/high static security finding(s) require remediation or explicit security review."})
    elif medium_findings:
        gates.append({"code": "MEDIUM_SECURITY_FINDINGS", "status": "review_required", "message": f"{len(medium_findings)} medium static security finding(s) require human review."})
    else:
        gates.append({"code": "SECURITY_FINDINGS_REVIEW", "status": "pass", "message": "No critical, high, or medium static security findings were supplied."})

    if evidence.behavioral_lift_pp is None:
        gates.append({"code": "BEHAVIORAL_LIFT", "status": "insufficient_evidence", "message": "Controlled baseline-versus-skill lift was not provided."})
    elif evidence.behavioral_lift_pp >= policy.minimum_behavioral_lift_pp:
        gates.append({"code": "BEHAVIORAL_LIFT", "status": "pass", "message": f"Lift {evidence.behavioral_lift_pp:.2f} pp meets minimum {policy.minimum_behavioral_lift_pp:.2f} pp."})
    else:
        gates.append({"code": "BEHAVIORAL_LIFT", "status": "fail", "message": f"Lift {evidence.behavioral_lift_pp:.2f} pp is below minimum {policy.minimum_behavioral_lift_pp:.2f} pp."})

    for code, label, value, minimum in (
        ("PAIRED_RUN_COUNT", "Paired run count", evidence.paired_runs, policy.minimum_paired_runs),
        ("MODEL_COVERAGE", "Measured model count", evidence.measured_models, policy.minimum_models),
    ):
        if value is None:
            gates.append({"code": code, "status": "insufficient_evidence", "message": f"{label} was not provided."})
        elif value >= minimum:
            gates.append({"code": code, "status": "pass", "message": f"{label} {value} meets minimum {minimum}."})
        else:
            gates.append({"code": code, "status": "insufficient_evidence", "message": f"{label} {value} is below minimum {minimum}."})

    if evidence.cost_overhead_percent is None:
        gates.append({"code": "COST_OVERHEAD", "status": "insufficient_evidence", "message": "Provider-reported cost overhead was not provided."})
    elif evidence.cost_overhead_percent <= policy.maximum_cost_overhead_percent:
        gates.append({"code": "COST_OVERHEAD", "status": "pass", "message": f"Cost overhead {evidence.cost_overhead_percent:.2f}% is within maximum {policy.maximum_cost_overhead_percent:.2f}%."})
    else:
        gates.append({"code": "COST_OVERHEAD", "status": "fail", "message": f"Cost overhead {evidence.cost_overhead_percent:.2f}% exceeds maximum {policy.maximum_cost_overhead_percent:.2f}%."})

    statuses = {gate["status"] for gate in gates}
    if "blocked" in statuses:
        decision = "blocked"
    elif "fail" in statuses:
        decision = "not_ready"
    elif "insufficient_evidence" in statuses:
        decision = "insufficient_evidence"
    elif "review_required" in statuses:
        decision = "human_review_required"
    else:
        decision = "eligible_for_human_approval"
    return {
        "assurance_version": "0.9.0",
        "policy_id": policy.policy_id,
        "decision": decision,
        "gates": gates,
        "automatic_certification": False,
        "limitations": "This report checks supplied evidence against thresholds. It does not verify evidence provenance, perform dynamic security testing, or replace an authorized human approver.",
    }
