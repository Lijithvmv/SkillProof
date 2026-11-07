from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance


def complete_evidence(**overrides):
    values = {
        "structural_score": 90,
        "instruction_quality_score": 85,
        "security_score": 95,
        "security_findings": [],
        "behavioral_lift_pp": 12.5,
        "paired_runs": 10,
        "measured_models": 2,
        "cost_overhead_percent": 15,
    }
    values.update(overrides)
    return AssuranceInput(**values)


def test_satisfactory_evidence_is_only_eligible_for_human_approval():
    report = evaluate_assurance(complete_evidence(), AssurancePolicy(policy_id="prod-v1"))
    assert report["decision"] == "eligible_for_human_approval"
    assert report["policy_id"] == "prod-v1"
    assert report["automatic_certification"] is False


def test_high_security_finding_blocks_readiness():
    report = evaluate_assurance(complete_evidence(security_findings=[{"code": "PROMPT_INJECTION_DIRECTIVE", "severity": "high"}]))
    assert report["decision"] == "blocked"


def test_missing_behavioral_and_cost_evidence_prevents_eligibility():
    report = evaluate_assurance(AssuranceInput(structural_score=90, instruction_quality_score=90, security_score=90))
    assert report["decision"] == "insufficient_evidence"


def test_failed_quality_gate_is_not_ready():
    report = evaluate_assurance(complete_evidence(structural_score=40))
    assert report["decision"] == "not_ready"
    assert next(g for g in report["gates"] if g["code"] == "STRUCTURAL_QUALITY")["status"] == "fail"


def test_medium_security_signal_requires_human_review():
    report = evaluate_assurance(complete_evidence(security_findings=[{"code": "EXCESSIVE_PRIVILEGE_REQUEST", "severity": "medium"}]))
    assert report["decision"] == "human_review_required"


def test_assurance_api_endpoint():
    from fastapi.testclient import TestClient
    from skillproof.api.main import app

    client = TestClient(app)
    response = client.post("/api/v1/evaluations/assurance", json={
        "evidence": {
            "structural_score": 90, "instruction_quality_score": 80, "security_score": 95,
            "behavioral_lift_pp": 10, "paired_runs": 5, "measured_models": 1,
            "cost_overhead_percent": 20,
        },
        "policy": {"policy_id": "demo", "minimum_paired_runs": 3},
    })
    assert response.status_code == 200
    assert response.json()["decision"] == "eligible_for_human_approval"

