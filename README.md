# SkillProof Foundation

SkillProof analyzes agent skill packages and returns deterministic, evidence-backed findings. Version 1.7 adds an optional OpenAI Responses API pilot adapter, a candidate three-task benchmark, blinded human review bundles, and grader/decision agreement metrics to the existing evaluation and governance foundation.

## Run locally

```powershell
git clone https://github.com/Lijithvmv/SkillProof.git
cd SkillProof
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn skillproof.api.main:app --reload
```

Open `http://localhost:8000/docs`. Upload a ZIP containing a skill directory with `SKILL.md` to `POST /api/v1/skills/intelligence`.

## API

`POST /api/v1/skills/intelligence` accepts a ZIP upload and returns the SHA-256 package fingerprint, selected skill path, file manifest, reference graph, progressive disclosure metrics, and structural findings. ZIP entries are checked for path traversal, symlinks, duplicate paths, and size limits before extraction into memory.

`POST /api/v1/skills/analyze` accepts a JSON object with a `files` mapping of relative paths to UTF-8 text, enabling deterministic analysis without ZIP packaging.

`POST /api/v1/skills/security` accepts the same JSON `files` mapping and returns a static security triage report. The full skill analysis also includes this report in its `security` field. Secret-like matched values are redacted from evidence.

`POST /api/v1/evaluations/assurance` checks supplied quality, security, behavioral, model-coverage, and cost evidence against a configurable policy. It reports blocked, not-ready, insufficient-evidence, human-review, or eligible-for-human-approval outcomes. It never automatically certifies a skill.

The Python service `skillproof.approvals.SQLiteApprovalStore` accepts only eligible assurance reports and creates a pending approval request with a canonical report hash. A different authenticated principal must approve, reject, or request changes. The store appends immutable audit events in SQLite. Authentication and authorization are supplied by the embedding application; no unauthenticated approval API is exposed.

The Python service `skillproof.history.EvaluationHistoryStore` stores experiment fingerprints and summary metrics in append-only SQLite history. It omits raw model outputs by default and compares the latest report with the most recent report using the same benchmark fingerprint. This is a persistence layer; authenticated API routes and retention controls belong to the embedding application.

The Python service `skillproof.registry.SQLiteSkillRegistry` catalogs immutable package fingerprints per tenant and skill name. New versions remain pending review (or are marked not eligible); promotion to active requires a separate human approval record matching the assurance report hash. The registry stores report summaries and an optional external `artifact_uri`, not skill package contents. The embedding application must authenticate and authorize tenant/actor IDs and resolve artifact URIs.

The `skillproof.authorization` module defines tenant roles (`tenant_admin`, `evaluator`, `approver`, `viewer`) and a `GovernanceAccess` façade for registry, approval, and evaluation history operations. When using this façade outside the HTTP API, the host application must create `Principal` objects from verified authentication claims.

For API SSO, configure `SKILLPROOF_AUTH_MODE=oidc`, `SKILLPROOF_OIDC_ISSUER`, `SKILLPROOF_OIDC_AUDIENCE`, and `SKILLPROOF_OIDC_JWKS_URL`. Optional claim settings are `SKILLPROOF_OIDC_ROLE_CLAIM` (default `skillproof_role`) and `SKILLPROOF_OIDC_TENANT_CLAIM` (default `tenant_id`). Access tokens must use the RFC 9068 `at+jwt` type and carry a recognized single role. Set `SKILLPROOF_ENV=production` to make startup fail unless OIDC mode is configured. In local development, authentication remains disabled unless OIDC mode is explicitly enabled. Health checks remain public; API routes require a bearer token in OIDC mode, and evaluation routes require the evaluator or tenant admin role.

For a local pilot with no API key, run Ollama and pass `--provider ollama` (see `examples/pilot/README.md`); it needs no extra package. For an OpenAI-backed pilot, install `pip install -e ".[dev,openai]"`. Set `OPENAI_API_KEY`, `SKILLPROOF_OPENAI_MODEL`, and `SKILLPROOF_OPENAI_GRADER_MODEL` to explicit values, then use the example in `examples/pilot/README.md`. The runner and grader use stateless Responses API calls (`store=False`), capture token and response metadata, and do not estimate dollar costs. The benchmark is a candidate that requires independent review. The pilot writes raw outputs, blinded review samples, and a separate unblinding key to the paths you specify; keep the key private until reviewers finish.

`skillproof grader-agreement completed-annotations.json unblinding-key.json` reports score error and pass/fail agreement after human scoring. Pass a second reviewer's file with `--extra-annotations reviewer-2.json` (repeatable; JSON array or JSONL). With two or more reviewers on the same samples, the report adds reviewer-to-reviewer agreement and Krippendorff's alpha for humans only and for humans plus the grader, so the grader is judged against how much people agree with each other. With a handful of samples these numbers are unstable. `skillproof decision-agreement labels.json --predicted-key automated_decision --human-key human_decision --labels eligible,not_ready,insufficient` reports categorical agreement for assurance or heuristic labels.

Install the package to get the `skillproof` command. `skillproof scan skill.zip --output report.json` runs structural and security triage, exiting nonzero for structural errors or critical/high security findings. `skillproof assurance-gate assurance-input.json --output decision.json` applies the supplied policy and emits a machine-readable decision. `skillproof monitor --history-db history.db --skill-key my-skill --output monitor.json` checks evaluation freshness, negative lift, regressions, model coverage, failure rate, and cost overhead; it is suitable for an external scheduled job. Monitor exits `0` when healthy, `1` when attention or an alert is required, and `4` for invalid configuration. Assurance gate exits `0` when eligible for human approval, `1` when human review is required, `2` when blocked/not ready, `3` when evidence is insufficient, and `4` for invalid input. A zero exit code never means approved or certified.

### Deciding on a skill update

SkillProof's main question is whether to replace one version of a skill with another.

- `skillproof manifest PKG` lists what a skill directory or ZIP can reach or change (network hosts and clients, process execution, writes to agent configuration such as `CLAUDE.md` or `.claude/settings.json`, persistence, credential access, package installs, destructive operations, bundled binaries). It decodes hidden content first (Base64, hex, character codes, split strings, escapes, zero-width and lookalike characters) and records each step. Nothing is executed and nothing is a verdict.
- `skillproof diff OLD NEW` reports only the capabilities the new version adds; it exits `1` when it adds any.
- `skillproof update-report OLD NEW` joins the capability diff with load rate (`--old-activation`, `--new-activation`), measured lift (`--old-pilot`, `--new-pilot`), grader-human agreement (`--agreement`) and, as a weaker separate column, a `grader-check` result on labelled answers (`--grader-check`, policy key `max_grader_disagreement_rate`). Missing evidence is listed. Without `--policy` it makes no decision; a policy file you write (for example `{"block_categories": ["agent_config_writes", "persistence"], "review_categories": "any", "min_load_rate": 0.8}`) turns the evidence into accept, review or block (exit `0`, `1`, `2`).
- `skillproof inventory ROOT...` checks every installed skill together: duplicate names (identical copies, or divergent versions where the copy an agent loads may not be the one you reviewed) and descriptions that compete for the same requests.
- `skillproof validate-findings REPORT DECISIONS` records confirmed or rejected decisions, each with a reviewer and a reason, on security findings, which all start as `needs_validation`.

`POST /api/v1/evaluations/tasks/validate` checks a proposed task against skill instructions for obvious phrase leakage, criteria wording exposure, unclear task action, ambiguity cues, and missing target behavior declarations. These checks are lexical signals and cannot certify task quality.

`POST /api/v1/evaluations/compare` accepts baseline and skill-enabled run scores on a 0–1 scale and reports mean score, population standard deviation, pass rate, absolute percentage-point lift, relative improvement, and negative lift.

Python integrations can call `skillproof.execution.execute_experiment(...)` with benchmark tasks, a runner implementing `run(prompt, context, skill_instructions)`, and an evaluator implementing `evaluate(task, output)`. It runs baseline and skill-enabled trials in seeded randomized order, records paired outputs, scores, model metadata, latency, usage and failures, then reports aggregate lift, pass-rate changes, paired latency/token/cost overhead, per-condition telemetry summaries, and model-specific lift/variance. No persistent storage is configured by default.

## Current scope

- Frontmatter parsing with duplicate YAML key detection and metadata type checks.
- Agent Skills metadata checks (`name`, `description`) and folder-name alignment.
- Relative Markdown reference graph, broken-link and orphan detection.
- Main-instruction size and progressive disclosure indicators.
- Findings carry stable codes, severity, message, and evidence.
- Instruction quality reports actionability, workflow sequence, prerequisite/output/verification/recovery coverage, vague phrases, and possible direct conflicts.
- Evaluation foundations validate benchmark task completeness/leakage cues and compare externally generated baseline and skill-enabled scores.
- Paired execution orchestration repeats both conditions, randomizes condition order with a recorded seed, and retains failed calls as zero-score records with error evidence.
- A local Ollama adapter (loopback only, standard library HTTP) and optional OpenAI Responses adapters run the same task with and without skill instructions and provide a blind structured rubric grade, using explicit model IDs.
- Candidate benchmark fixtures and blind human-review tooling measure grader score agreement and automated decision agreement after annotations are entered.
- Static security triage flags suspicious instruction overrides, exfiltration, dangerous shell/dependency patterns, broad permission requests, credential patterns, credential-like filenames, and external links for review.
- Operational reports summarize provider-reported latency, token usage and cost, including paired overhead and missing telemetry counts.
- Compatibility summaries aggregate paired baseline and skill-enabled runs by provider and exact model ID, flagging regressions and material lift variation.
- Assurance policies apply configurable thresholds and explicitly require human approval; missing behavioral, model, or cost evidence prevents an eligible decision.
- Human approval workflow records report hashes, enforces submitter/reviewer separation, and protects audit events against update or deletion.
- Evaluation history stores instruction and benchmark fingerprints with summary metrics, and reports skill-lift regressions against a comparable benchmark run.
- Tenant-scoped registry records package versions and allows only separately reviewed, hash-matched assurance reports to promote an active version.
- CLI scan and assurance-gate commands return stable JSON artifacts and nonzero exit codes for CI policy failures.
- Scheduled monitoring checks evaluation freshness, lift regressions, model coverage, run failures, and cost overhead, emitting machine-readable alerts.
- Tenant role checks gate registry, approval, and evaluation history operations; approval records are tenant-scoped in SQLite.

Scores are diagnostic summaries, not certification. The candidate benchmark has not been independently reviewed and no human annotations or live OpenAI results are included. Instruction, task, and security checks are heuristic; security scans do not execute adversarial tests or prove a skill safe. Execution isolation, production database operations, and external notification delivery still require integration work.
