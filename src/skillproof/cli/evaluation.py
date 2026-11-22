"""Evaluation commands: conformance benchmarks from a skill's own rules, runs with and without the skill, the paired
pilot with blind human review, grader checks and agreement, and monitoring of recorded runs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillproof.engines.activation import measure_activation, read_distractors, read_requests, read_skill_card
from skillproof.engines.evaluation import validate_benchmark_task
from skillproof.engines.execution import execute_experiment
from skillproof.engines.grader_check import check_grader, read_cases
from skillproof.storage.history import EvaluationHistoryStore
from skillproof.engines.human_review import HumanAnnotation, compare_decision_agreement, compare_score_agreement, create_blind_review_bundle
from skillproof.engines.monitoring import monitor_skill_history
from skillproof.adapters.ollama import OllamaActivationProbe, OllamaEvaluator, OllamaRunner
from skillproof.adapters.openai_responses import OpenAIResponsesEvaluator, OpenAIResponsesRunner
from skillproof.engines.pilot import load_benchmark, read_manifest
from skillproof.wiring import close_governance

from skillproof.cli.common import catalogue_at, read_annotation_rows, skill_text, write_json

Result = tuple[dict[str, Any], int]


def benchmark_draft(args) -> dict[str, Any]:
    from skillproof.engines.conformance import draft_benchmark, extract_claims, write_benchmark
    from skillproof.adapters.ollama import ollama_json_asker

    text = skill_text(args.skill)
    claims = extract_claims(text)
    if not claims["claims"]:
        raise ValueError("no claims found in SKILL.md (no rules, steps or 'Use when' requests)")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "claims.json").write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
    ask = ollama_json_asker(args.model, args.ollama_url, seed=args.seed)
    if args.mode == "templates":
        from skillproof.engines.templates import generate_benchmark

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
    from skillproof.engines.checks import CheckedEvaluator
    from skillproof.engines.conformance import adherence, extract_claims

    text = skill_text(args.skill)
    tasks = load_benchmark(args.benchmark)
    manifest = read_manifest(args.benchmark)
    claims_path = Path(args.benchmark).with_name("claims.json")
    claims = json.loads(claims_path.read_text(encoding="utf-8")) if claims_path.exists() else extract_claims(text)
    judge = OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed) if args.grader_model else None
    runner: Any
    skill_manifest = None
    if args.sandbox:
        # The agent acts through tools in a sandbox; the skill's own files are in its workspace (skill-enabled runs).
        from skillproof import package
        from skillproof.adapters.ollama import OllamaToolRunner
        from skillproof.engines.capabilities import build_manifest

        folder = Path(args.skill)
        files, _ = package.read_folder(folder.parent if folder.name == "SKILL.md" else folder)
        skill_manifest = build_manifest(files)
        runner = OllamaToolRunner(model=args.model, skill_files=files, base_url=args.ollama_url, seed=args.seed,
                                  max_output_tokens=args.max_output_tokens, max_steps=args.max_steps, sandbox_base=args.sandbox_dir)
    else:
        runner = OllamaRunner(model=args.model, base_url=args.ollama_url, seed=args.seed, max_output_tokens=args.max_output_tokens)
    experiment = execute_experiment(tasks=tasks, skill_instructions=text, runner=runner, evaluator=CheckedEvaluator(judge),
                                    repeats=args.repeats, seed=args.seed, skill_manifest=skill_manifest)
    experiment["comparison"]["adherence"] = adherence(experiment, claims)
    if args.load_rate:
        experiment["comparison"]["load_rate"] = measure_load_rate(args, [task.prompt for task in tasks],
                                                                  experiment["comparison"].get("skill_lift_percentage_points"))
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


def measure_load_rate(args, relevant: list[str] | None, forced_lift: float | None) -> dict[str, Any]:
    """How often a model picks the skill from its description among the skills it competes with: the installed
    skills whose descriptions are closest to it (the ones most likely to be picked instead), plus any listed in
    --distractor-skills. Relevant requests are given (benchmark prompts, --requests) or, when None, written from the
    skill's description by a local model (engines/requests.py). Unrelated ones come from --unrelated-tasks, plus
    near misses written for the closest rivals when --near-misses is above 0."""
    from skillproof.engines.activation import SkillCard
    from skillproof.engines.installed import default_roots
    from skillproof.engines.inventory import installed_cards, rank_similar

    folder = Path(args.skill)
    target = read_skill_card(folder if folder.name == "SKILL.md" else folder / "SKILL.md")
    roots = [Path(r) for r in args.competitors_root] or default_roots()
    pool = [(name, description) for name, description in installed_cards(roots) if name != target.name]
    generated: dict[str, Any] | None = None
    ask = None
    near = getattr(args, "near_misses", 0) or 0
    if relevant is None or near:
        from skillproof.adapters.ollama import ollama_json_asker

        generator = getattr(args, "generator_model", None) or args.model
        ask = ollama_json_asker(generator, args.ollama_url, temperature=0.7, seed=args.seed, max_output_tokens=2000)
    if relevant is None:
        from skillproof.engines.requests import write_requests

        assert ask is not None
        relevant, dropped = write_requests(target.name, target.description, ask, getattr(args, "generate", 6))
        if not relevant:
            raise ValueError(f"no usable request could be written from the description ({len(dropped)} dropped)")
        generated = {"source": "generated_from_descriptions", "model": getattr(args, "generator_model", None) or args.model,
                     "relevant": relevant, "near_misses": [], "dropped": dropped}
    ranked = rank_similar(target.description, pool, args.competitors)
    semantic: dict[str, Any] = {"status": "off"}
    matched: list[dict[str, Any]] = []
    if getattr(args, "embed_model", None):
        # Rivals by meaning: the installed skills that best match the requests this skill is for, as a loader matches.
        from skillproof.adapters.ollama import OllamaEmbedder
        from skillproof.engines.inventory import rank_by_requests

        try:
            matched = rank_by_requests(relevant, pool, OllamaEmbedder(model=args.embed_model, base_url=args.ollama_url).embed,
                                       args.competitors)
            semantic = {"status": "used", "model": args.embed_model}
        except (RuntimeError, ValueError, OSError) as exc:
            semantic = {"status": "unavailable", "reason": str(exc)[:300]}  # reported, never silent
    listed = read_distractors(args.distractor_skills) if args.distractor_skills else []
    cards, names = [], {target.name}
    for card in ([SkillCard(name=r["name"], description=r["description"]) for r in ranked + matched] + listed):
        if card.name not in names and card.name != "none":
            names.add(card.name)
            cards.append(card)
    if not cards:
        raise ValueError("no competing skills found for the load-rate test: pass --competitors-root or --distractor-skills")
    unrelated = read_requests(args.unrelated_tasks) if args.unrelated_tasks else []
    if near:
        # Near misses: requests for the closest rivals (by request match when available), which this skill must not take.
        from skillproof.engines.requests import write_requests

        assert ask is not None
        generated = generated or {"source": "generated_from_descriptions", "model": getattr(args, "generator_model", None) or args.model,
                                  "relevant": [], "near_misses": [], "dropped": []}
        rivals = [(r["name"], r["description"]) for r in (matched or ranked)[:getattr(args, "rivals", 3)]]
        for rival_name, rival_description in rivals:
            kept, lost = write_requests(rival_name, rival_description, ask, near)
            generated["near_misses"].extend({"rival": rival_name, "request": text} for text in kept)
            generated["dropped"].extend(lost)
        unrelated = unrelated + [item["request"] for item in generated["near_misses"]]
    probe = OllamaActivationProbe(model=args.model, base_url=args.ollama_url, seed=args.seed)
    result = measure_activation(target=target, distractors=cards, relevant_requests=relevant,
                                unrelated_requests=unrelated,
                                probe=probe, repeats=args.load_repeats, seed=args.seed, forced_lift_percentage_points=forced_lift)
    records = result.pop("records", None) or []  # by_request keeps the per-request picture; single choices are not needed later
    result["failure_reasons"] = sorted({r["error"] for r in records if r.get("error")})[:10]  # why a choice could not be made
    by_name: dict[str, dict[str, Any]] = {}
    for r in ranked:
        by_name.setdefault(r["name"], {"name": r["name"]})["similarity"] = r["similarity"]
    for r in matched:
        by_name.setdefault(r["name"], {"name": r["name"]})["request_match"] = r["request_match"]
    result["competitors"] = {
        "source": "installed skills" + (" and --distractor-skills" if listed else ""),
        "installed_available": len(pool),
        "selection": (f"the {len(ranked)} installed skills with the most similar descriptions (word overlap)"
                      + (f" and the {len(matched)} that best match the skill's own requests (embeddings)" if matched else "")),
        "semantic": semantic,
        "used": list(by_name.values()) + [{"name": c.name, "listed": True} for c in listed],
    }
    result["model"] = args.model
    if generated is not None:
        generated["limitations"] = ("Written by a local model from the descriptions alone and checked only for naming the "
                                    "skill, copying its description and duplicates. A near miss written for a rival can still "
                                    "be a fair request for this skill when the two overlap; read them before trusting the rate.")
        result["requests"] = generated
    return result


def load_rate_failed(load: dict[str, Any]) -> bool:
    from skillproof.config import settings

    rate, false_rate = (load.get("relevant") or {}).get("activation_rate"), (load.get("unrelated") or {}).get("false_activation_rate")
    return (rate is not None and rate < settings().min_load_rate) or (false_rate is not None and false_rate > settings().max_false_load_rate)


def run_load_rate(args) -> Result:
    if getattr(args, "near_misses", None) is None:
        args.near_misses = 0 if args.requests else 2
    try:
        result = measure_load_rate(args, read_requests(args.requests) if args.requests else None, None)
        return result, 1 if load_rate_failed(result) or result["failures"] else 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_benchmark_draft(args) -> Result:
    try:
        return benchmark_draft(args), 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_evaluate_skill(args) -> Result:
    try:
        result = evaluate_skill(args)
        followed = (result["comparison"].get("adherence") or {}).get("adherence_rate")
        behaviour = (result["comparison"].get("behaviour") or {}).get("decision")
        load = result["comparison"].get("load_rate") or {}
        if load and load_rate_failed(load):
            behaviour = behaviour or "load_rate"
        return result, 1 if (sum(result["failure_counts"].values()) or (followed is not None and followed < 0.7)
                             or behaviour in {"block", "ask", "load_rate"}) else 0
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
    evaluate.add_argument("--sandbox", action="store_true", help="Let the agent act through tools (files, commands, URLs) in a sandbox and record what it does: protected writes, the canary credential, and behaviour the skill's files do not show. Commands are recorded, never run. Exit 1 when the skill causes block- or ask-level behaviour.")
    evaluate.add_argument("--max-steps", type=int, default=12, help="Tool calls per sandboxed run.")
    evaluate.add_argument("--sandbox-dir", help="Folder for the temporary workspaces (default: the system temp folder).")
    evaluate.add_argument("--load-rate", action="store_true", help="Also measure how often the model picks this skill from its description among the installed skills it competes with (the most similar descriptions). Exit 1 when it is picked for fewer relevant requests than SKILLPROOF_MIN_LOAD_RATE or for more unrelated ones than SKILLPROOF_MAX_FALSE_LOAD_RATE.")
    evaluate.add_argument("--embed-model", default="nomic-embed-text", help="Local Ollama embedding model used to add rivals by meaning: the installed skills that best match the skill's own requests. Pass '' to use word overlap only.")
    evaluate.add_argument("--competitors", type=int, default=15, help="How many of the most similar installed skills compete with it.")
    evaluate.add_argument("--competitors-root", action="append", default=[], help="Folder of installed skills to draw competitors from; repeat. Default: common agent locations.")
    evaluate.add_argument("--distractor-skills", help="JSONL of extra competing skills (name, description).")
    evaluate.add_argument("--unrelated-tasks", help="JSONL of prompts the skill should NOT be picked for (false load rate).")
    evaluate.add_argument("--near-misses", type=int, default=0, help="With --load-rate: requests to write for each of the closest rivals, which the skill must not take.")
    evaluate.add_argument("--rivals", type=int, default=3)
    evaluate.add_argument("--generator-model", help="Local model that writes near misses (default: --model).")
    evaluate.add_argument("--load-repeats", type=int, default=3, help="Choices per request (the skill list is shuffled each time).")
    evaluate.add_argument("--name", help="Catalogue skill name to record under (default: the SKILL.md name).")
    evaluate.add_argument("--data-dir", help="Catalogue storage to record into (as catalogue-import). Omit to only report.")
    evaluate.add_argument("--tenant", default="local")
    evaluate.add_argument("--output", default="-")
    evaluate.set_defaults(run=run_evaluate_skill)

    load = commands.add_parser("load-rate", help="How often a local model picks this skill from its description, among the installed skills whose descriptions are closest to it, for requests it is for (--requests) and for unrelated ones. A quick check of a description; to put it in the catalogue's decision use evaluate-skill --load-rate. Exit 1 below SKILLPROOF_MIN_LOAD_RATE or above SKILLPROOF_MAX_FALSE_LOAD_RATE.")
    load.add_argument("skill", help="Skill folder (holding SKILL.md).")
    load.add_argument("--requests", help="JSONL of prompts the skill is for ({\"prompt\": ...}). Omit to have the local model write them from the description (checked: no skill name, no copied phrase), with near misses for the closest rivals.")
    load.add_argument("--generate", type=int, default=6, help="Requests to write from the description when --requests is omitted.")
    load.add_argument("--near-misses", type=int, default=None, help="Requests to write for each of the closest rivals, which the skill must not take (default 2 when generating, else 0).")
    load.add_argument("--rivals", type=int, default=3, help="How many of the closest rivals get near misses.")
    load.add_argument("--generator-model", help="Local model that writes requests (default: --model).")
    load.add_argument("--unrelated-tasks", help="JSONL of prompts the skill should NOT be picked for.")
    load.add_argument("--model", required=True, help="Local Ollama model that chooses.")
    load.add_argument("--ollama-url", default=conf.ollama_url)
    load.add_argument("--embed-model", default="nomic-embed-text", help="Local Ollama embedding model used to add rivals by meaning: the installed skills that best match the skill's own requests. Pass '' to use word overlap only.")
    load.add_argument("--competitors", type=int, default=15)
    load.add_argument("--competitors-root", action="append", default=[])
    load.add_argument("--distractor-skills")
    load.add_argument("--load-repeats", type=int, default=3)
    load.add_argument("--seed", type=int, default=0)
    load.add_argument("--output", default="-")
    load.set_defaults(run=run_load_rate)

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
