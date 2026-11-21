"""The worker that turns a queued evaluation job into run evidence on a catalogue version.

For one version: claims from its SKILL.md -> tests built from the skill's own rules (templates; the local model writes
only the request and background) -> the agent runs every test with and without the skill -> adherence per claim and
lift -> the experiment is recorded in the tenant's history -> the version, if still waiting for a decision, is assessed
again on every run recorded for its exact SKILL.md. Settings come from the environment the service reads.
"""
from __future__ import annotations

import logging
import threading
import traceback
from dataclasses import dataclass
from typing import Any, Callable

from skillproof.authorization import GovernanceAccess, Principal
from skillproof.checks import CheckedEvaluator
from skillproof.conformance import adherence, extract_claims
from skillproof.config import settings
from skillproof.evidence import instructions_fingerprint
from skillproof.execution import execute_experiment
from skillproof.jobs import JobStore
from skillproof.logs import log
from skillproof.services import alerts, catalogue
from skillproof.templates import generate_benchmark


@dataclass(frozen=True)
class EvaluationSettings:
    model: str                       # the agent model the skill is measured on
    draft_model: str                 # writes request + background for the generated tests
    ollama_url: str = "http://127.0.0.1:11434"
    tasks: int = 6
    repeats: int = 2
    seed: int = 7
    max_output_tokens: int = 3000

    @classmethod
    def from_env(cls) -> "EvaluationSettings | None":
        current = settings()
        if not current.evaluation.enabled:
            return None
        return cls(model=current.evaluation.model, draft_model=current.evaluation.draft_model or current.evaluation.model,
                   ollama_url=current.ollama_url, tasks=current.evaluation.tasks, repeats=current.evaluation.repeats)


def run_job(governance: GovernanceAccess, tenant_id: str, job: dict[str, Any], settings: EvaluationSettings, *,
            ask: Callable[[str, dict], str] | None = None, runner: Any | None = None) -> dict[str, Any]:
    """Produce run evidence for the job's version. Returns the job result (stored by the caller)."""
    from skillproof.ollama_adapter import OllamaRunner, ollama_json_asker

    skill_md = job["payload"]["skill_md"]
    if instructions_fingerprint(skill_md) != job["payload"]["instructions_fingerprint"]:
        raise ValueError("the SKILL.md text in the job does not match the fingerprint it was queued with")
    claims = extract_claims(skill_md)
    ask = ask or ollama_json_asker(settings.draft_model, settings.ollama_url, seed=settings.seed)
    drafted = generate_benchmark(skill_md, claims, ask, tasks=settings.tasks, skill_name=job["skill_name"])
    base = {"coverage": drafted["coverage"], "tests_rejected": len(drafted["rejected"]),
            "rules_not_covered": len(drafted["uncovered"]), "model": settings.model}
    if not drafted["tasks"]:
        return {**base, "outcome": "no_tests",
                "message": "None of this skill's answer-visible rules has a shape SkillProof can build a test for yet; "
                           "no run evidence was produced. Attach an experiment recorded with evaluate-skill instead."}
    runner = runner or OllamaRunner(model=settings.model, base_url=settings.ollama_url, seed=settings.seed,
                                    max_output_tokens=settings.max_output_tokens)
    experiment = execute_experiment(tasks=drafted["tasks"], skill_instructions=skill_md, runner=runner,
                                    evaluator=CheckedEvaluator(None), repeats=settings.repeats, seed=settings.seed)
    experiment["comparison"]["adherence"] = adherence(experiment, claims)
    experiment["benchmark"] = {"benchmark_id": f"{job['skill_name']}-generated", "version": "generated",
                               "validation_status": "generated_from_rules"}
    worker = Principal(user_id="evaluation-job", tenant_id=tenant_id, role="evaluator")
    stored = governance.record_evaluation(worker, experiment, skill_key=job["skill_name"])
    comparison = experiment["comparison"]
    result = {**base, "outcome": "measured", "experiment_id": stored["experiment_id"], "tests": len(drafted["tasks"]),
              "lift_pp": comparison.get("skill_lift_percentage_points"), "interpretation": comparison.get("interpretation"),
              "adherence_rate": comparison["adherence"]["adherence_rate"], "baseline_rate": comparison["adherence"]["baseline_rate"],
              "broken_claims": [c["claim"] for c in comparison["adherence"]["broken_with_skill"]],
              "failures": experiment["failure_counts"]}
    version = governance.get_skill(worker, job["version_id"])
    try:
        updated = catalogue.reassess_on_runs(governance, worker, version, skill_md)
    except ValueError as exc:
        result["assurance"] = f"not reassessed: {exc}"
        return result
    if updated is None:
        result["assurance"] = f"not reassessed: the version is {version['state']} and keeps the report it was approved on"
        return result
    result["assurance"] = updated["assurance"]["decision"]
    result["state"] = updated["state"]
    return result


def work_once(governance: GovernanceAccess, settings: EvaluationSettings, **kwargs: Any) -> dict[str, Any] | None:
    """Run the next queued job, if any. Returns the finished job, or None when the queue is empty."""
    jobs: JobStore = governance.jobs
    claimed = jobs.claim()
    if claimed is None:
        return None
    tenant_id, job = claimed
    base = {"job_id": job["job_id"], "version_id": job["version_id"], "skill_name": job["skill_name"]}
    log("evaluation_started", tenant=tenant_id, **base)
    try:
        done = jobs.finish(tenant_id, job["job_id"], run_job(governance, tenant_id, job, settings, **kwargs))
        result = done["result"] or {}
        summary = {k: result.get(k) for k in ("outcome", "adherence_rate", "baseline_rate", "broken_claims", "lift_pp", "assurance")}
        alerts.emit(governance, tenant_id, "evaluation.finished", {**base, **summary})
        log("evaluation_finished", tenant=tenant_id, **base, **summary)
        return done
    except Exception as exc:  # a failed job is recorded with its reason; the worker keeps going
        alerts.emit(governance, tenant_id, "evaluation.failed", {**base, "error": f"{type(exc).__name__}: {exc}"[:300]})
        log("evaluation_failed", logging.ERROR, tenant=tenant_id, **base, error=f"{type(exc).__name__}: {exc}"[:300])
        return jobs.fail(tenant_id, job["job_id"], f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}")


def start_worker(make_governance: Callable[[], GovernanceAccess | None], settings: EvaluationSettings,
                 stop: threading.Event, idle_seconds: float = 5.0) -> threading.Thread:
    """One background thread with its own storage connections, running jobs one at a time until `stop` is set."""
    def loop() -> None:
        governance = make_governance()
        if governance is None or governance.jobs is None:
            return
        governance.jobs.recover()
        while not stop.is_set():
            if work_once(governance, settings) is None:
                stop.wait(idle_seconds)
    thread = threading.Thread(target=loop, name="skillproof-evaluation", daemon=True)
    thread.start()
    return thread
