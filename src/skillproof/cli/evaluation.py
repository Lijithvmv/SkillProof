"""Evaluation commands: conformance benchmarks from a skill's own rules, runs with and without the skill, the paired
pilot with blind human review, grader checks and agreement, and monitoring of recorded runs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillproof.activation import measure_activation, read_distractors, read_requests, read_skill_card
from skillproof.evaluation import validate_benchmark_task
from skillproof.execution import execute_experiment
from skillproof.grader_check import check_grader, read_cases
from skillproof.history import EvaluationHistoryStore
from skillproof.human_review import HumanAnnotation, compare_decision_agreement, compare_score_agreement, create_blind_review_bundle
from skillproof.monitoring import monitor_skill_history
from skillproof.ollama_adapter import OllamaActivationProbe, OllamaEvaluator, OllamaRunner
from skillproof.openai_adapter import OpenAIResponsesEvaluator, OpenAIResponsesRunner
from skillproof.pilot import load_benchmark, read_manifest
from skillproof.wiring import close_governance

from skillproof.cli.common import catalogue_at, read_annotation_rows, skill_text, write_json

Result = tuple[dict[str, Any], int]


def benchmark_draft(args) -> dict[str, Any]:
    from skillproof.conformance import draft_benchmark, extract_claims, write_benchmark
    from skillproof.ollama_adapter import ollama_json_asker

    text = skill_text(args.skill)
    claims = extract_claims(text)
    if not claims["claims"]:
        raise ValueError("no claims found in SKILL.md (no rules, steps or 'Use when' requests)")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "claims.json").write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
    ask = ollama_json_asker(args.model, args.ollama_url, seed=args.seed)
    if args.mode == "templates":
        from skillproof.templates import generate_benchmark

        drafted = generate_benchmark(text, claims, ask, tasks=args.tasks)
        status = "generated_from_rules"
        review = {"coverage": drafted["coverage"], "rejected": drafted["rejected"], "uncovered": drafted["uncovered"],
                  "task_reviews": drafted["reviews"]}
    else:
        drafted = draft_benchmark(text, claims, ask, tasks=args.tasks)
        status = "draft_needs_review"
        review = {"dropped": drafted["dropped"], "task_reviews": drafted["reviews"]}
    write_benchmark(out / "benchmark.jsonl", drafted["tasks"], skill=claims["skill"], claims_file="claims.json",
                    generator=f"{args.mode}:{args.model}", status=status)
    (out / "draft-review.json").write_text(json.dumps(review, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"skill": claims["skill"], "claims": len(claims["claims"]), "mode": args.mode, "tasks": len(drafted["tasks"]),
            "checks": sum(len(t.checks) for t in drafted["tasks"]), "coverage": drafted.get("coverage"),
            "status": status, "output_dir": str(out)}


def evaluate_skill(args) -> dict[str, Any]:
    from skillproof.authorization import Principal
    from skillproof.checks import CheckedEvaluator
    from skillproof.conformance import adherence, extract_claims

    text = skill_text(args.skill)
    tasks = load_benchmark(args.benchmark)
    manifest = read_manifest(args.benchmark)
    claims_path = Path(args.benchmark).with_name("claims.json")
    claims = json.loads(claims_path.read_text(encoding="utf-8")) if claims_path.exists() else extract_claims(text)
    judge = OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed) if args.grader_model else None
    runner = OllamaRunner(model=args.model, base_url=args.ollama_url, seed=args.seed, max_output_tokens=args.max_output_tokens)
    experiment = execute_experiment(tasks=tasks, skill_instructions=text, runner=runner, evaluator=CheckedEvaluator(judge),
                                    repeats=args.repeats, seed=args.seed)
    experiment["comparison"]["adherence"] = adherence(experiment, claims)
    experiment["benchmark"] = {"benchmark_id": manifest.get("benchmark_id"), "version": manifest.get("version"),
                               "validation_status": manifest.get("status")}
    name = args.name or claims.get("skill") or Path(args.skill).name
    if args.data_dir:
        governance = catalogue_at(Path(args.data_dir))
        try:
            stored = governance.record_evaluation(Principal(user_id="skill-evaluation", tenant_id=args.tenant, role="evaluator"),
                                                  experiment, skill_key=name)
        finally:
            close_governance(governance)
        experiment["recorded"] = {"skill_name": name, "tenant": args.tenant, "experiment_id": stored["experiment_id"]}
    return experiment


def run_benchmark_draft(args) -> Result:
    try:
        return benchmark_draft(args), 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_evaluate_skill(args) -> Result:
    try:
        result = evaluate_skill(args)
        followed = (result["comparison"].get("adherence") or {}).get("adherence_rate")
        return result, 1 if sum(result["failure_counts"].values()) or (followed is not None and followed < 0.7) else 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_monitor(args) -> Result:
    store = EvaluationHistoryStore(args.history_db)
    try:
        result = monitor_skill_history(store, args.skill_key, max_age_days=args.max_age_days, minimum_models=args.minimum_models,
                                       maximum_failure_rate=args.maximum_failure_rate,
                                       maximum_cost_overhead_percent=args.maximum_cost_overhead_percent,
                                       regression_threshold_pp=args.regression_threshold_pp)
        return result, 0 if result["status"] == "healthy" else 1
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}, 4
    finally:
        store.close()


def run_pilot(args) -> Result:
    try:
        if not args.model or not args.grader_model:
            raise ValueError("Set explicit --model and --grader-model values, or configure SKILLPROOF_MODEL and SKILLPROOF_GRADER_MODEL.")
        if args.provider == "ollama":
            runner = OllamaRunner(model=args.model, base_url=args.ollama_url, seed=args.seed, temperature=args.temperature)
            evaluator = OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed)
        else:
            runner = OpenAIResponsesRunner(model=args.model)
            evaluator = OpenAIResponsesEvaluator(model=args.grader_model)
        skill_instructions = Path(args.skill_file).read_text(encoding="utf-8")
        tasks = load_benchmark(args.benchmark)
        manifest = read_manifest(args.benchmark)
        task_reviews = [validate_benchmark_task(skill_instructions, task) for task in tasks]
        experiment = execute_experiment(tasks=tasks, skill_instructions=skill_instructions, runner=runner, evaluator=evaluator,
                                        repeats=args.repeats, seed=args.seed)
        experiment["benchmark"] = {"benchmark_id": manifest.get("benchmark_id"), "version": manifest.get("version"), "validation_status": manifest.get("status")}
        if args.distractor_skills:
            if args.provider != "ollama":
                raise ValueError("The load-rate test currently needs --provider ollama.")
            experiment["activation"] = measure_activation(
                target=read_skill_card(args.skill_file), distractors=read_distractors(args.distractor_skills),
                relevant_requests=[task.prompt for task in tasks],
                unrelated_requests=read_requests(args.unrelated_tasks) if args.unrelated_tasks else [],
                probe=OllamaActivationProbe(model=args.model, base_url=args.ollama_url, seed=args.seed, temperature=args.temperature),
                repeats=args.repeats, seed=args.seed, forced_lift_percentage_points=experiment["comparison"].get("skill_lift_percentage_points"))
        elif args.unrelated_tasks:
            raise ValueError("--unrelated-tasks needs --distractor-skills.")
        bundle = create_blind_review_bundle(experiment, tasks, task_reviews)
        write_json({key: bundle[key] for key in ("review_samples", "annotation_template", "task_review_samples", "task_review_template", "instructions")},
                   args.review_output)
        write_json(bundle["sealed_unblinding_key"], args.unblinding_key_output)
        failures = sum(experiment["failure_counts"].values())
        return experiment, 2 if failures == len(tasks) * args.repeats * 2 else 1 if failures else 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_grader_check(args) -> Result:
    try:
        if not args.grader_model:
            raise ValueError("Set --grader-model or SKILLPROOF_GRADER_MODEL.")
        evaluator = (OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed)
                     if args.provider == "ollama" else OpenAIResponsesEvaluator(model=args.grader_model))
        result = check_grader(load_benchmark(args.benchmark), read_cases(args.cases), evaluator)
        return result, 1 if result["disagreements"] or result["grader_failures"] else 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_grader_agreement(args) -> Result:
    try:
        rows = [row for path in [args.annotations, *args.extra_annotations] for row in read_annotation_rows(path)]
        key_data = json.loads(Path(args.unblinding_key).read_text(encoding="utf-8"))
        annotations = [HumanAnnotation.model_validate(item) for item in rows]
        return compare_score_agreement(annotations, key_data, pass_threshold=args.pass_threshold, tolerance=args.tolerance), 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"error": str(exc)}, 4


def run_decision_agreement(args) -> Result:
    try:
        rows = json.loads(Path(args.annotations).read_text(encoding="utf-8"))
        return compare_decision_agreement(rows, predicted_key=args.predicted_key, human_key=args.human_key,
                                          labels=[x.strip() for x in args.labels.split(",") if x.strip()]), 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    draft = commands.add_parser("benchmark-draft", help="Read what a skill says about itself (claims) and draft a conformance benchmark that tests them, with a local model. The draft must be reviewed before its results count.")
    draft.add_argument("skill", help="Skill folder (holding SKILL.md).")
    draft.add_argument("--model", required=True, help="Local Ollama model that drafts the tasks.")
    draft.add_argument("--ollama-url", default=conf.ollama_url)
    draft.add_argument("--tasks", type=int, default=8)
    draft.add_argument("--mode", choices=("templates", "model"), default="templates",
                       help="templates: tests built from the rule's own words, the model writes only background (default); "
                            "model: the model drafts whole tests (needs review).")
    draft.add_argument("--seed", type=int, default=0)
    draft.add_argument("--output-dir", required=True, help="Writes claims.json, benchmark.jsonl, manifest.json and draft-review.json here.")
    draft.add_argument("--output", default="-", help="Summary destination; use - for stdout.")
    draft.set_defaults(run=run_benchmark_draft)

    evaluate = commands.add_parser("evaluate-skill", help="Run a skill's benchmark with and without the skill on a local model, measure lift and claim adherence, and record it in the catalogue's history so the catalogue cites it.")
    evaluate.add_argument("skill", help="Skill folder (holding SKILL.md).")
    evaluate.add_argument("--benchmark", required=True, help="benchmark.jsonl (claims.json beside it is used for adherence).")
    evaluate.add_argument("--model", required=True, help="Agent model (local Ollama).")
    evaluate.add_argument("--grader-model", help="Judge for free-text criteria; not needed for a checks-only benchmark.")
    evaluate.add_argument("--ollama-url", default=conf.ollama_url)
    evaluate.add_argument("--repeats", type=int, default=2)
    evaluate.add_argument("--seed", type=int, default=0)
    evaluate.add_argument("--max-output-tokens", type=int, default=3000)
    evaluate.add_argument("--name", help="Catalogue skill name to record under (default: the SKILL.md name).")
    evaluate.add_argument("--data-dir", help="Catalogue storage to record into (as catalogue-import). Omit to only report.")
    evaluate.add_argument("--tenant", default="local")
    evaluate.add_argument("--output", default="-")
    evaluate.set_defaults(run=run_evaluate_skill)

    monitor = commands.add_parser("monitor", help="Check persisted evaluation history for regressions and stale results.")
    monitor.add_argument("--history-db", required=True, help="SQLite evaluation history database path.")
    monitor.add_argument("--skill-key", required=True, help="Skill history key to monitor.")
    monitor.add_argument("--max-age-days", type=float, default=30)
    monitor.add_argument("--minimum-models", type=int, default=1)
    monitor.add_argument("--maximum-failure-rate", type=float, default=0.1)
    monitor.add_argument("--maximum-cost-overhead-percent", type=float, default=100)
    monitor.add_argument("--regression-threshold-pp", type=float, default=5)
    monitor.add_argument("--output", default="-", help="Monitor report destination; use - for stdout.")
    monitor.set_defaults(run=run_monitor)

    pilot = commands.add_parser("pilot", help="Run a paired agent/grader pilot on a JSONL benchmark (OpenAI or local Ollama).")
    pilot.add_argument("--skill-file", required=True)
    pilot.add_argument("--benchmark", required=True)
    pilot.add_argument("--provider", choices=["openai", "ollama"], default=conf.pilot_provider, help="openai needs OPENAI_API_KEY; ollama runs locally with no key.")
    pilot.add_argument("--ollama-url", default=conf.ollama_url, help="Loopback Ollama server for --provider ollama.")
    pilot.add_argument("--seed", type=int, default=0, help="Order randomization seed, and the sampling seed for Ollama.")
    pilot.add_argument("--temperature", type=float, default=0.7, help="Ollama agent sampling temperature (the grader always uses 0).")
    pilot.add_argument("--distractor-skills", help="JSONL of other skills (name, description). Turns on the load-rate test (Ollama only).")
    pilot.add_argument("--unrelated-tasks", help="JSONL of prompts the skill should NOT be picked for (false activation).")
    pilot.add_argument("--model", default=conf.pilot_model or None, help="Agent model ID; defaults to SKILLPROOF_MODEL or SKILLPROOF_OPENAI_MODEL.")
    pilot.add_argument("--grader-model", default=conf.pilot_grader_model or None, help="Grader model ID; defaults to SKILLPROOF_GRADER_MODEL or SKILLPROOF_OPENAI_GRADER_MODEL.")
    pilot.add_argument("--repeats", type=int, default=2)
    pilot.add_argument("--output", required=True, help="Experiment report JSON path.")
    pilot.add_argument("--review-output", required=True, help="Blind review bundle JSON path.")
    pilot.add_argument("--unblinding-key-output", required=True, help="Keep this separate from reviewers until scoring is complete.")
    pilot.set_defaults(run=run_pilot)

    gcheck = commands.add_parser("grader-check", help="Grade answers with known per-criterion labels and list where the grader disagrees. Exit 1 on any disagreement or grader failure.")
    gcheck.add_argument("--benchmark", required=True)
    gcheck.add_argument("--cases", required=True, help="JSONL of case_id, task_id, output, expected (one 0/1 per criterion), note.")
    gcheck.add_argument("--provider", choices=["openai", "ollama"], default=conf.pilot_provider)
    gcheck.add_argument("--ollama-url", default=conf.ollama_url)
    gcheck.add_argument("--grader-model", default=conf.pilot_grader_model or None)
    gcheck.add_argument("--seed", type=int, default=0)
    gcheck.add_argument("--output", default="-")
    gcheck.set_defaults(run=run_grader_check)

    agreement = commands.add_parser("grader-agreement", help="Compare completed human scores to blinded grader scores.")
    agreement.add_argument("annotations", help="Completed annotations (JSON array or JSONL) of sample_id, human_score, reviewer_id, rationale objects.")
    agreement.add_argument("unblinding_key", help="Separate unblinding key JSON from the pilot run.")
    agreement.add_argument("--extra-annotations", action="append", default=[], metavar="FILE", help="Another reviewer's completed annotations; repeat once per file.")
    agreement.add_argument("--pass-threshold", type=float, default=0.7)
    agreement.add_argument("--tolerance", type=float, default=0.1)
    agreement.add_argument("--output", default="-", help="Agreement report destination; use - for stdout.")
    agreement.set_defaults(run=run_grader_agreement)

    decision = commands.add_parser("decision-agreement", help="Measure automated decision agreement with human labels.")
    decision.add_argument("annotations", help="JSON array containing automated and human decision labels.")
    decision.add_argument("--predicted-key", required=True)
    decision.add_argument("--human-key", required=True)
    decision.add_argument("--labels", required=True, help="Comma-separated complete label set.")
    decision.add_argument("--output", default="-", help="Agreement report destination; use - for stdout.")
    decision.set_defaults(run=run_decision_agreement)
