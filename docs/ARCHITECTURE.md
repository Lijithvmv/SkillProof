# SkillProof architecture: review, decisions, and the feature inventory

Reviewed 2026-11-22 against production software standards, on the code at `01d435e` (10,483 lines in `src/`, 350
tests, CI green on Python 3.11 to 3.13 and on the container image). Every finding below points at code.

## Verdict

The product is feature-complete for a governed skill catalogue, and its security boundaries (tenant row-level
security, OIDC, two-person approval, append-only audit, SSRF-checked webhooks) are real and tested on SQLite and
PostgreSQL. It is **not yet production-grade as software**: one identity defect, no layering between interface,
service and storage code, duplicated business logic, configuration read from the environment in nine modules,
schema changes without migrations, single-connection storage, `print` instead of logging, and no lint or type gate.

## Defects (fix first)

| # | Defect | Evidence | Consequence |
|---|---|---|---|
| D1 | One skill has two identities. Uploads are fingerprinted over decoded text (`analyzer.analyze_files`), installed folders over raw bytes (`catalogue_import._package`). | ncr-writeup: folder `124b532c…`, the same files as a ZIP `7874e3d5…`. | A version approved by upload never matches its installed copy: `catalogue-check` and the fleet report flag it as running unapproved forever. |
| D2 | Assurance is assembled in two places with different rules (`api/main.py` register_version, `catalogue_import._assurance`). | `grep AssuranceInput(` | Upload and import can judge the same package differently; every new gate must be added twice. |
| D3 | HTTP status chosen by matching message text. | `api/main.py`: `404 if "not found" in str(exc) else 409` | A reworded message changes the API contract. |

## Standards gaps

| Area | Now | Production standard |
|---|---|---|
| Layering | Routes hold business logic; `authorization.GovernanceAccess` mixes access control, orchestration, alerts and fleet logic; private helpers imported across modules (`_package`, `_installed_families`, `_read_installed`). | Interface → service → repository → engine, each with one job; only public functions cross a boundary. |
| Module size | `capabilities.py` 1,771 lines; `cli.py` 633; `api/main.py` 599. | One concern per module; API routers and CLI commands per area. |
| Configuration | Environment read in 9 modules. | One typed settings object, validated at start. |
| Schema | Tables created at import; columns added ad hoc (`ALTER TABLE` in `registry.__init__`); the app role needs CREATE. | Versioned migrations, run once, recorded. |
| Storage | One connection per store guarded by a lock: every request on that store is serialised. | A connection per request/transaction from a pool. |
| Logging | `print` in the service; no request ids. | Structured logs with request id, tenant and actor. |
| Domain types | Versions, jobs and reports are `dict[str, Any]` end to end. | Typed models at service boundaries. |
| Quality gates | Tests only. | Lint and type check in CI. |

## Decisions

1. **One canonical package identity**: SHA-256 over every file's path and raw bytes (sorted), the scheme installed
   folders already use. Uploads, imports, evaluation and fleet reports all use it (`skillproof.package`).
2. **One catalogue service** owns registration, assessment, re-assessment, promotion, rollback, marks and policy; the
   API, the CLI importer and the evaluation worker call it. Access control stays a separate, thin layer.
3. **Typed errors** (`NotFound`, `Conflict`, `Forbidden`, `InvalidInput`) map to HTTP status in one place.
4. **Target layout**, reached in stages with compatibility imports so nothing that uses the old module paths breaks:

Reached (2026-11-22):

```
skillproof/
  engines/     analyzer, semantic, security, capabilities/, triage, confidence, second_opinion, conformance,
               templates, evaluation, execution, checks, grader_check, activation, compatibility, operations,
               human_review, update_report, inventory, installed, apm_lock, monitoring, pilot
  storage/     database (pool, migrations, row-level security), registry, approvals, history, jobs, notify, fleet, artifacts (package bytes)
  services/    catalogue, imports, evaluation (jobs worker), alerts, fleet, distribution (sync)
  adapters/    ollama, openai_responses
  api/         main + routers/ + deps          cli/   analysis, catalogue, evaluation, operations
  config, errors, models, package, ingestion, logs, wiring, service, authorization, oidc
  governance, evidence   (stay at the top level until another session's edits are committed; then engines/)
```

Planned:

```
skillproof/
  config.py        settings          errors.py      typed errors
  package.py       reading packages + canonical fingerprint
  engines/         analysis, capabilities (split), triage, confidence, conformance, templates, evaluation, assurance
  storage/         database, migrations, repositories (registry, approvals, history, jobs, notify, fleet, artifacts)
  services/        catalogue, evaluation (jobs + worker), alerts, fleet, imports, distribution
  api/             app + one router per area           web/   catalogue page
  cli/             one module per command group        adapters/   ollama, openai
```

5. **Order**: correctness (D1–D3) → operability (settings, logging, migrations, connection handling) → structure
   (routers, CLI, capabilities split, packages) → quality gates (lint, types). Each stage lands with the full suite
   green on SQLite and PostgreSQL.

## Progress

| Item | Status | Commit |
|---|---|---|
| D1 one package identity (and zipped folders rooted at the skill folder) | done, regression test | 1575411 |
| D2 one catalogue service for assessment and re-assessment | done | 1575411 |
| D3 typed errors mapped by type | done | 1575411 |
| PostgreSQL connection pool, one connection per transaction per thread (also fixed: a statement could land in another thread's transaction) | done, concurrency test | 2b5a7c7 |
| Versioned migrations, `skillproof migrate`, verify mode | done, checked on a real pre-migration catalogue | 0ecf3a9 |
| Structured JSON logs with request ids | done | 217181f |
| Lint gate in CI (found: an undefined name in dead code, 16 unused imports) | done | 183544a |
| API split into routers + shared dependencies (same 39 routes) | done | b540226 |
| One settings module (40 settings, validated; production refuses to start with problems) | done | 079120d |
| CLI split by command group (23 of 24 help texts identical; one store factory for API and CLI) | done | 7e03fca |
| `capabilities.py` split into a package (six modules, one-way dependencies, all 194 names still importable) | done | 6f4df32 |
| Alerts and fleet orchestration out of the access layer into services | done | 992d093 |
| Typed models at service boundaries; type check in CI (24 layered files clean) | done | 4cae529 |
| Package layout: engines/, storage/, adapters/, services/ (33 modules moved; every old import path aliases the moved module) | done; governance.py and evidence.py stay in place until another session's edits to them are committed | see git log |

## Feature inventory (nothing may be lost)

Every feature below keeps its tests; the suite must stay green through every stage.

| Feature | Where now | Tests |
|---|---|---|
| ZIP intake checks (traversal, symlinks, sizes, duplicates) | ingestion | test_ingestion_api |
| Structure and authoring rules, reference graph | analyzer | test_analyzer |
| Instruction quality heuristics | semantic | test_semantic |
| Static security scan + reviewer validation | security | test_security |
| Capability manifest, decoding, diff, reach, hooks | capabilities | test_capabilities (99) |
| Triage block/ask/note, combinations, rarity, confidence | triage, confidence | test_triage, test_confidence |
| Local-model second opinion | second_opinion | test_second_opinion |
| Conformance: claims, adherence, model drafts | conformance | test_conformance |
| Tests from rule shapes | templates | test_templates |
| Paired runs, task-level statistics, calibration gate | execution, checks, grader_check | test_execution, test_grader_check |
| Load rate | activation | test_activation |
| Cross-model compatibility, cost and latency | compatibility, operations | test_compatibility |
| Blind human review, kappa, Krippendorff's alpha | human_review | test_pilot |
| Ollama and OpenAI adapters | ollama_adapter, openai_adapter | test_ollama, test_pilot |
| Assurance gates incl. adherence and capability change | governance | test_governance, test_conformance, test_evaluation_jobs |
| Run evidence bound to the SKILL.md | evidence | test_conformance, test_registry_api |
| Registry: versions, compare, promote with acknowledgement, marks, re-assess, rollback, tenant policy | registry | test_registry, test_registry_api, test_registry_lifecycle |
| Two-person approval with append-only audit | approvals | test_approvals |
| Evaluation history, regressions, monitor | history, monitoring | test_history, test_monitoring |
| Evaluation jobs and worker | jobs, evaluation_jobs | test_evaluation_jobs |
| Signed webhook alerts | notify | test_notify |
| Fleet reporting | fleet | test_notify |
| Package store and sync (enforcement) | storage/artifacts, services/distribution, cli sync | test_sync |
| Installed-skill import, installed-vs-approved check | catalogue_import | test_catalogue_import, test_conformance |
| Watch installed skills and plugins | installed | test_installed |
| APM lockfile check | apm_lock | test_apm_lock |
| Inventory: duplicates, competing descriptions | inventory | test_inventory |
| Update decision report | update_report | test_update_report |
| RBAC roles incl. reporter | authorization | test_authorization |
| OIDC tokens, page sign-in with PKCE | oidc, web | test_oidc, test_page_sign_in |
| Tenant isolation on PostgreSQL | storage | test_postgres_isolation (+ whole suite on PostgreSQL) |
| Service: config, readiness, backups, restore, service files | service | test_service |
| CLI: 23 commands | cli | test_cli and per-feature tests |
| API: 35 routes | api/main | per-feature API tests |
| Container image | Dockerfile | CI `image` job |
