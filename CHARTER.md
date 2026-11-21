# CHARTER — SkillProof

DIRECTION: A governed registry and market for agent skills — analyse a skill, measure whether it does what it says, and gate every version promotion with two-person approval, capability-change acknowledgement and fleet enforcement. A security-and-governance platform; the capability diff is one engine inside it, not the product.

<!-- Lock this shape once Lijith confirms the wording:
       node ../levelwith/scripts/charter-check.mjs CHARTER.md --lock
     After that a silent edit to DIRECTION fails the check until a re-lock. A change of shape is
     Lijith's recorded call — never a quiet rewrite, and never a narrowing memory rule (the past drift
     was "a decision tool for skill updates / capability diff", which dropped most of the pieces below). -->

Every "progress" claim names one PIECE below and its STATUS. "built" needs an EVIDENCE pointer a reader
can open; a precision %, a commit, or a renamed positioning line is not a piece. A blocked piece stays
listed as blocked until it is built — it is not routed around with easier work.

## PIECE: capability engine (manifest, decode, diff, reach, triage, confidence)
STATUS: built
EVIDENCE: src/skillproof/capabilities.py; tests/test_capabilities.py (99 cases); held-out 5/6 precision table in README.md — risk-category precision 73.9-77%, about 1 risk alarm in 4 a false alarm (measured on unseen repos, not yet at a target; single labeller)

## PIECE: registry + catalogue (versions, compare, promote-with-acknowledgement, marks, rollback, tenant policy)
STATUS: built
EVIDENCE: tests/test_registry.py, tests/test_registry_api.py, tests/test_registry_lifecycle.py

## PIECE: two-person approval with append-only audit
STATUS: built
EVIDENCE: tests/test_approvals.py (submitter/reviewer separation, audit protected from update/delete)

## PIECE: assurance policy + capability-change gate
STATUS: built
EVIDENCE: tests/test_governance.py; README assurance-gate / CAPABILITY_CHANGE gate

## PIECE: conformance — does the skill do what it says (claims, adherence, model-drafted tests, evaluate-skill)
STATUS: built
EVIDENCE: tests/test_conformance.py; README benchmark-draft / evaluate-skill (CLAIM_ADHERENCE gate)

## PIECE: evaluation jobs + worker (the server measures skills itself)
STATUS: built
EVIDENCE: tests/test_evaluation_jobs.py

## PIECE: catalogue page + RBAC + OIDC sign-in (PKCE)
STATUS: built
EVIDENCE: tests/test_page_sign_in.py, tests/test_oidc.py, tests/test_authorization.py

## PIECE: signed webhook alerts (SSRF-checked, retried)
STATUS: built
EVIDENCE: tests/test_notify.py

## PIECE: storage — tenant row-level security (PostgreSQL + SQLite), backups, restore
STATUS: built
EVIDENCE: tests/test_postgres_isolation.py; tests/test_service.py; whole suite runs on PostgreSQL

## PIECE: fleet enforcement across machines (fleet-report, catalogue-check: approved vs running)
STATUS: blocked
BLOCKER: D1 identity defect (docs/ARCHITECTURE.md) — uploads are fingerprinted over decoded text, installed folders over raw bytes, so an upload-approved version never matches its installed copy and reads as running-unapproved forever. The canonical-identity fix (in the architecture piece) unblocks it. Listed, not routed around.

## PIECE: production-grade software architecture (canonical identity D1, one catalogue service D2, typed errors D3, layering, versioned migrations, connection pool, one settings object, structured logging, typed domain, lint+type gate)
STATUS: designed
EVIDENCE: docs/ARCHITECTURE.md — target layout + staged order, reviewed at 01d435e; not yet implemented. This is the architecture-before-more-features piece.

## PIECE: the market half (sharing / distributing governed skills beyond one tenant's own registry)
STATUS: designed
EVIDENCE: direction only — named in the committed vision, no design doc or code yet. Kept here so it is not quietly dropped back to "a scanner".
