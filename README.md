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

## Run as a service

Copy `deploy/skillproof.example.toml` to `skillproof.toml`, set storage and sign-in, then:

```powershell
skillproof serve --config skillproof.toml                     # the API and the catalogue page
skillproof backup --config skillproof.toml                    # a backup now (also scheduled while serving)
skillproof restore --config skillproof.toml --from <backup>   # SQLite: hashes checked, server must be stopped
skillproof service-file --config skillproof.toml --kind systemd       # or --kind windows-task
```

- **Storage.** `[storage] database_url` uses PostgreSQL (`pip install -e ".[postgres]"`); `data_dir` uses SQLite files on one machine. In PostgreSQL every table with tenant data has row-level security forced for every role, and every transaction sets its tenant first: a query with no tenant sees nothing and a row cannot be written for another tenant. Connect as a role that is neither superuser nor `BYPASSRLS`. Audit tables are append-only by trigger on both backends.
- **Health.** `/health` is liveness; `/health/ready` queries every store and answers 503 when storage is missing or unreachable.
- **Backups.** SQLite uses its online backup API (a consistent copy while serving), PostgreSQL uses `pg_dump`. A backup appears only when complete, carries a manifest of SHA-256 hashes, and the newest `keep` are retained.
- **Sign-in.** With OIDC on, the page signs people in with the authorization code flow and PKCE as a public client (`[auth] client_id`, redirect URI `https://<host>/catalogue`). The access token is kept in memory only. `scripts/dev_oidc_provider.py` is a local provider for trying it; plain-HTTP issuers are accepted only on loopback and never with `environment = "production"`.
- **Tests on PostgreSQL.** `python scripts/pg_test_server.py init` (with `SKILLPROOF_PG_BIN` pointing at a PostgreSQL bin folder) starts a loopback test server; with `SKILLPROOF_TEST_PG_URL` set, the whole test suite runs on PostgreSQL as well as SQLite.

## How accurate the capability engine is

Measured on public skill repositories the engine had never seen, with the sample, labels and pass rules written down before any result was read (single labeller; a second reader has not checked the labels):

| Held-out test | Repositories | Precision, all items | Precision, risk categories only | Missed updates |
|---|---|---|---|---|
| 5 | 26 | 91.0% [86.2, 94.2] | 73.9% [62.5, 82.8] | 0 of 100 |
| 6 | 26 | 89.5% [84.5, 93.0] | **77.0% [67.8, 84.2]** | 0 of 100 |

"Risk categories" means hosts, installs, execution, credentials, agent-config writes, clients, hooks and similar, without declared tools and bundled files. About one risk alarm in four on unseen skills is a false alarm, mostly a command or address that is only mentioned, described or listed. Reviewers can mark those (below), and each mark becomes a labelled example for the next round.

## API

`POST /api/v1/skills/intelligence` accepts a ZIP upload and returns the SHA-256 package fingerprint, selected skill path, file manifest, reference graph, progressive disclosure metrics, and structural findings. ZIP entries are checked for path traversal, symlinks, duplicate paths, and size limits before extraction into memory.

`POST /api/v1/skills/analyze` accepts a JSON object with a `files` mapping of relative paths to UTF-8 text, enabling deterministic analysis without ZIP packaging.

`POST /api/v1/skills/security` accepts the same JSON `files` mapping and returns a static security triage report. The full skill analysis also includes this report in its `security` field. Secret-like matched values are redacted from evidence.

`POST /api/v1/evaluations/assurance` checks supplied quality, security, behavioral, model-coverage, and cost evidence against a configurable policy. It reports blocked, not-ready, insufficient-evidence, human-review, or eligible-for-human-approval outcomes. It never automatically certifies a skill.

The Python service `skillproof.approvals.ApprovalStore` (SQLite or PostgreSQL) accepts only eligible assurance reports and creates a pending approval request with a canonical report hash. A different authenticated principal must approve, reject, or request changes. The store appends immutable audit events (append-only by trigger). Authentication and authorization are supplied by the embedding application; no unauthenticated approval API is exposed.

The Python service `skillproof.history.EvaluationHistoryStore` stores experiment fingerprints and summary metrics in append-only history (SQLite or PostgreSQL). It omits raw model outputs by default and compares the latest report with the most recent report using the same benchmark fingerprint. This is a persistence layer; authenticated API routes and retention controls belong to the embedding application.

The Python service `skillproof.registry.SkillRegistry` (SQLite or PostgreSQL) catalogs immutable package fingerprints per tenant and skill name. New versions remain pending review (or are marked not eligible); promotion to active requires a separate human approval record matching the assurance report hash. The registry stores report summaries and an optional external `artifact_uri`, not skill package contents. The embedding application must authenticate and authorize tenant/actor IDs and resolve artifact URIs.

### Skill catalogue API

Set `SKILLPROOF_DATA_DIR` to a folder for the registry, approval and history databases. Then:

1. `POST /api/v1/registry/versions` uploads a skill ZIP. Run evidence comes either from recorded experiments (`experiment_ids`, below; each must have run this exact `SKILL.md`) or, marked as declared rather than measured, from `evidence_json` (lift, paired runs, models, cost). SkillProof analyses the package itself; static scores are never taken from the caller. It builds the capability manifest and compares it with the tenant's active version of the same skill, then ranks every addition block / ask / note. The assurance report is bound to this exact package, so approving one version can never promote another.
2. `POST /api/v1/registry/versions/{id}/approval-requests` sends an eligible version for review.
3. `POST /api/v1/approvals/{request_id}/decision` lets a different person approve, reject or request changes.
4. `POST /api/v1/registry/versions/{id}/promote` makes the version active. The capability change is compared again at this point, because another version may have become active in the meantime. If the change has a block-level addition, promotion also needs `capability_ack` set to that change's `change_hash`, so the approver confirms the exact lines they read. The acknowledgement is written to the append-only audit trail.
5. `GET /api/v1/registry/catalogue` lists each skill with its active version and every version waiting for a decision. `GET /api/v1/registry/skills/{name}/versions` and `GET /api/v1/registry/versions/{id}` show the history and the full change.

`skillproof catalogue-import --data-dir <same folder>` feeds the skills installed on the machine into the catalogue. It searches the common Claude, Codex, Cursor and VS Code locations, or the folders you pass with `--root`. A skill whose folder hasn't changed is recognised by its fingerprint and skipped before any analysis. A changed skill becomes a new version, compared with the active one, or with the previous version while nothing is approved yet. Skills that share a name across agents get the agent's label, for example `pptx (codex)`. Installed skills come with static evidence only, so they stay `insufficient_evidence` until run evidence is added. The command exits 1 when an update has a block-level addition, so it can run on a schedule.

`skillproof catalogue-check` compares the skills installed on the machine with the versions the catalogue approved, without registering anything: `approved`, `never_approved`, or `running_unapproved` (the installed folder differs from its approved version), with what the installed version adds over the approved one when it was registered. It exits 1 on `running_unapproved` (and with `--strict` on `never_approved`), so it can run on a schedule as the enforcement side of the catalogue.

A reviewer who reads a raised item and finds it is not a real capability marks it (`POST /api/v1/registry/versions/{id}/false-alarms`, or **Not real** on the page) with a reason. The person who registered the version cannot mark its items. The same item with evidence in the same files is not raised again for that skill; the same value in a new file is. Dismissed items are listed, do not count toward the decision, and are part of the change hash. Every mark is audited and exported as a labelled example (`GET /api/v1/registry/false-alarms`) for tuning the engine.

**Does the skill do what it says?** `skillproof benchmark-draft SKILL_DIR --model <local model> --output-dir DIR` reads what the SKILL.md says about itself: the requests it is for, its rules (never / always / must) and its steps. It writes them to `claims.json` and asks a local model to draft scenarios whose exact checks each name one claim (`[C11] flags the NCR as blocking`). Phrases a rule commits to ("say \"not checked\"", "never \"0 parts\"") become checks by themselves. The draft is marked `draft_needs_review`; a person fixes or deletes its tasks before the results count. `skillproof evaluate-skill SKILL_DIR --benchmark DIR/benchmark.jsonl --model <local model> --data-dir <catalogue>` runs it with and without the skill, reports lift and **adherence per claim** (with the skill and without it, and which claims the agent broke), and records the result in the catalogue's history. `catalogue-import` then cites the runs recorded for that exact SKILL.md, so the version's assurance is measured rather than `insufficient_evidence`; a measured adherence below the policy's `minimum_adherence_rate` (default 70%) fails the `CLAIM_ADHERENCE` gate. A version still waiting for a decision is assessed again when runs for it are recorded later (an approval made on the old report must be requested again); an approved version keeps its report and new runs are listed under `evidence_not_attached`. The default policy allows at most 100% cost overhead, measured as provider cost or, when the provider reports none (local models), as extra input tokens. A large skill can exceed that by far (a 21 KB SKILL.md measured +2,750% input tokens per call), so it stops at `not_ready` until the tenant decides that cost is acceptable: pass a policy with a higher `maximum_cost_overhead_percent` to `catalogue-import --policy`. The limit is the tenant's decision, not raised by default.

**The server measures skills itself.** With `[evaluation] model` set in the service configuration, uploading a version with `evaluate=true`, `POST /api/v1/registry/versions/{id}/evaluate`, or **Run evidence** on the page queues a job. A background worker (one job at a time) builds tests from the skill's own rules, runs them with and without the skill on the local model, records the experiment and assesses the version again; `GET /api/v1/registry/versions/{id}/jobs` and the page show its state, adherence and outcome. A skill none of whose rules has a supported shape gets `no_tests`, said plainly, instead of invented tests.

**Tenant policy and the capability gate.** `GET /api/v1/policy` shows the tenant's assurance policy; `PUT /api/v1/policy` (tenant admins) stores it, with every change kept. Upload, import and evaluation jobs all judge versions on it. The capability engine's result is a gate (`CAPABILITY_CHANGE`): by default a block-level addition is acknowledged by the approver at promotion; with `block_level_capabilities = "require_review"` it stops approval until a security review.

`POST /api/v1/evaluations/experiments` records an `execute_experiment` result's metrics in the tenant's history for a skill, so versions can cite it. The assurance report says whether its behavioural evidence was measured (with experiment ids and models), declared by the uploader, or absent, and the page shows it.

The page at `/catalogue` (`/` redirects there) lists skills with a search box and a level filter. Selecting a version shows what it adds, its assurance gates, its approval state and its audit trail, along with the actions your role allows.

Roles decide who can act: an evaluator uploads and submits, an approver decides and promotes, and a viewer can only read. With OIDC off (local development), the tenant is `local` and identity comes from the `X-SkillProof-Dev-User` and `X-SkillProof-Dev-Role` headers. Production mode refuses to start without OIDC.

The `skillproof.authorization` module defines tenant roles (`tenant_admin`, `evaluator`, `approver`, `viewer`) and a `GovernanceAccess` façade for registry, approval, and evaluation history operations. When using this façade outside the HTTP API, the host application must create `Principal` objects from verified authentication claims.

For API SSO, configure `SKILLPROOF_AUTH_MODE=oidc`, `SKILLPROOF_OIDC_ISSUER`, `SKILLPROOF_OIDC_AUDIENCE`, and `SKILLPROOF_OIDC_JWKS_URL`. Optional claim settings are `SKILLPROOF_OIDC_ROLE_CLAIM` (default `skillproof_role`) and `SKILLPROOF_OIDC_TENANT_CLAIM` (default `tenant_id`). Access tokens must use the RFC 9068 `at+jwt` type and carry a recognized single role. Set `SKILLPROOF_ENV=production` to make startup fail unless OIDC mode is configured. In local development, authentication remains disabled unless OIDC mode is explicitly enabled. Health checks remain public; API routes require a bearer token in OIDC mode, and evaluation routes require the evaluator or tenant admin role.

For a local pilot with no API key, run Ollama and pass `--provider ollama` (see `examples/pilot/README.md`); it needs no extra package. For an OpenAI-backed pilot, install `pip install -e ".[dev,openai]"`. Set `OPENAI_API_KEY`, `SKILLPROOF_OPENAI_MODEL`, and `SKILLPROOF_OPENAI_GRADER_MODEL` to explicit values, then use the example in `examples/pilot/README.md`. The runner and grader use stateless Responses API calls (`store=False`), capture token and response metadata, and do not estimate dollar costs. The benchmark is a candidate that requires independent review. The pilot writes raw outputs, blinded review samples, and a separate unblinding key to the paths you specify; keep the key private until reviewers finish.

`skillproof grader-agreement completed-annotations.json unblinding-key.json` reports score error and pass/fail agreement after human scoring. Pass a second reviewer's file with `--extra-annotations reviewer-2.json` (repeatable; JSON array or JSONL). With two or more reviewers on the same samples, the report adds reviewer-to-reviewer agreement and Krippendorff's alpha for humans only and for humans plus the grader, so the grader is judged against how much people agree with each other. With a handful of samples these numbers are unstable. `skillproof decision-agreement labels.json --predicted-key automated_decision --human-key human_decision --labels eligible,not_ready,insufficient` reports categorical agreement for assurance or heuristic labels.

Install the package to get the `skillproof` command. `skillproof scan skill.zip --output report.json` runs structural and security triage, exiting nonzero for structural errors or critical/high security findings. `skillproof assurance-gate assurance-input.json --output decision.json` applies the supplied policy and emits a machine-readable decision. `skillproof monitor --history-db history.db --skill-key my-skill --output monitor.json` checks evaluation freshness, negative lift, regressions, model coverage, failure rate, and cost overhead; it is suitable for an external scheduled job. Monitor exits `0` when healthy, `1` when attention or an alert is required, and `4` for invalid configuration. Assurance gate exits `0` when eligible for human approval, `1` when human review is required, `2` when blocked/not ready, `3` when evidence is insufficient, and `4` for invalid input. A zero exit code never means approved or certified.

### Deciding on a skill update

SkillProof's main question is whether to replace one version of a skill with another.

- `skillproof manifest PKG` lists what a skill directory or ZIP can reach or change (network hosts and clients, process execution, writes to agent configuration such as `CLAUDE.md` or `.claude/settings.json`, persistence, credential access, package installs, destructive operations, bundled binaries). It decodes hidden content first (Base64, hex, character codes, split strings, escapes, zero-width and lookalike characters) and records each step. Nothing is executed and nothing is a verdict.
- `skillproof diff OLD NEW` reports only the capabilities the new version adds, plus facts both versions have whose reach grew: a recursive delete that moved from a temp or build folder to the home folder or filesystem root, a hook whose matcher went from named tools to every tool, an allowed tool that went from `Bash(git:*)` to `Bash`. A hook counts as added only when an event gains a handler; pointing an existing hook at a different script is listed separately. The `triage` block ranks every addition and widening as `block` (do not apply without reading these lines), `ask` (confirm it is expected) or `note` (routine). It explains each one with a reason and counts how many of 7,717 real public skill updates added the same fact. It also flags dangerous pairs in one shipped file: a secret read plus an outbound call, a download plus execution, a hook that reaches the network, an instructions write plus a remote fetch. Exit `1` when the update adds or widens anything.
- `skillproof lock-check apm.lock.yaml` reads each git dependency (`repo_url`, `resolved_commit`, `resolved_ref`, `virtual_path`) from a Microsoft APM lockfile, clones it bare into a local cache (nothing is checked out), and diffs every skill folder at the locked commit against the update target (`--to`, or by default the tip of the locked branch or the newest semver tag). Lockfile drift says that bytes or commits changed; this says what the update would let each skill do that it cannot do now. Exit `1` when an update adds capabilities.
- `skillproof watch-installed` finds every installed SKILL.md (common Claude, Codex, Cursor and VS Code locations, or `--root`), keeps a local state file of capability manifests (not skill contents), and on each run reports what every changed skill adds since the last run. A skill is matched across updates by its install path with version and hash folders removed, so an update that lands in a new editor build or extension version is still compared with the old one. The first run also diffs older copies still on disk. Oversized files are fingerprinted and listed as not scanned instead of hiding the skill. Exit `1` when an update adds capabilities.
- `skillproof update-report OLD NEW` joins the capability diff with load rate (`--old-activation`, `--new-activation`), measured lift (`--old-pilot`, `--new-pilot`), grader-human agreement (`--agreement`) and, as a weaker separate column, a `grader-check` result on labelled answers (`--grader-check`, policy key `max_grader_disagreement_rate`). Missing evidence is listed. Without `--policy` it makes no decision; a policy file you write (for example `{"block_categories": ["agent_config_writes", "persistence"], "review_categories": "any", "min_load_rate": 0.8}`) turns the evidence into accept, review or block (exit `0`, `1`, `2`).
- `skillproof inventory ROOT...` checks every installed skill together: duplicate names (identical copies, or divergent versions where the copy an agent loads may not be the one you reviewed) and descriptions that compete for the same requests.
- `skillproof validate-findings REPORT DECISIONS` records confirmed or rejected decisions, each with a reviewer and a reason, on security findings, which all start as `needs_validation`.

`POST /api/v1/evaluations/tasks/validate` checks a proposed task against skill instructions for obvious phrase leakage, criteria wording exposure, unclear task action, ambiguity cues, and missing target behavior declarations. These checks are lexical signals and cannot certify task quality.

`POST /api/v1/evaluations/compare` accepts baseline and skill-enabled run scores on a 0–1 scale and reports mean score, population standard deviation, pass rate, absolute percentage-point lift, relative improvement, and negative lift.

**Checks before judges.** A benchmark task can carry typed `checks` (text present or absent, regex, a JSON path value, a number recomputed within a tolerance, word limits, a heading) besides free-text `criteria`. `skillproof.checks.CheckedEvaluator` scores the checks exactly and asks the model judge only about the criteria; each criterion counts once, and every experiment reports its share of exact checks. When a benchmark has judged criteria, the grader must first pass labelled calibration answers (`calibration_cases`, graded with `grader_check`): more than one broken criterion passed, more than 15% disagreement, or grader failures withhold the lift, with the reason. A checks-only benchmark needs no calibration.

Python integrations can call `skillproof.execution.execute_experiment(...)` with benchmark tasks, a runner implementing `run(prompt, context, skill_instructions)`, and an evaluator implementing `evaluate(task, output)`. It runs baseline and skill-enabled trials in seeded randomized order, records paired outputs, scores, model metadata, latency, usage and failures, then reports aggregate lift on complete pairs, its uncertainty with the task as the unit (exact sign-flip p-value, bootstrap interval over tasks, tasks improved/worse/unchanged; the interpretation is "positive" or "negative" only when the interval excludes zero and the exact p-value is at most 0.05), pass-rate changes, paired latency/token/cost overhead, per-condition telemetry summaries, and model-specific lift/variance. No persistent storage is configured by default.

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

Scores are diagnostic summaries, not certification. The candidate benchmark has not been independently reviewed and no human annotations or live OpenAI results are included. Instruction, task, and security checks are heuristic; security scans do not execute adversarial tests or prove a skill safe. Execution isolation and external notification delivery still require integration work; the capability engine's precision on unseen skills is measured above, not assumed.
