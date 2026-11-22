# What SkillProof needs to succeed: real-world gaps (2026-11-22)

Grounded in the sources studied for SkillProof (Snyk skill analysis, Tessl's evaluation framework, NVIDIA
SkillSpector and SkillEvaluator, Cisco skill-scanner, Microsoft APM lockfiles, Copilot Cowork's skill import,
Perplexity's self-improving skills, AgentPilot, a skill optimizer built on evolutionary search, Sophos' decode-then-
judge work) and in SkillProof's own code.

## The market reports; nobody controls

| Who | What they do | What they do not do |
|---|---|---|
| Skill scanners (Snyk, Cisco, SkillSpector) | Flag patterns in one version | Decide which version may run; Snyk flags 64.7% of popular skills, so a flag decides little |
| SkillEvaluator | Scores skills in CI (static tiers, live runs) | Compare versions' content; control installs |
| APM lockfiles | Pin and detect drift (bytes, refs) | Say what a change lets a skill do; stop an unapproved one |
| Copilot Cowork | Imports skill packages between hosts | Validate user-created skills |
| Self-improving agents (Perplexity, AgentPilot, optimizers) | Write and update skills automatically, many per user | Review what an update lets the skill do; format checks only |

SkillProof already answers the questions the others skip: what an update adds, whether the skill follows its own
rules, and who approved it. But until now it only **reported** a skill running unapproved on a machine. It could not
put the approved version back, could not stop the unapproved one, and did not keep the approved package bytes.

## The gaps, in order of what success depends on

1. **Enforcement (control, not reporting).** Keep every registered package's bytes, content-addressed and bound to
   its fingerprint; let each machine pull the tenant's approved set and reconcile: approved versions installed,
   changed or unapproved copies quarantined (reversible), every installed file verified against the approved
   fingerprint before it is written. Without this, SkillProof is one more report.
2. **Machine-authored updates.** Skills are increasingly written and updated by agents themselves. Each version
   needs provenance (human or agent, from what), and policy must hold an agent-written update to at least the bar
   of a new skill; an agent can never approve its own update.
3. **Tool-using skills.** Most real skills act through tools; their behaviour can only be proven in a sandbox that
   records what the agent does (file writes, processes, network) against protected-path rules.
4. **Load rate in the decision.** A skill that is never picked does nothing (Tessl: loaded in 41% of tasks unforced
   vs 98% forced); the catalogue should show and gate on it.

Gap 1 is built: the package store, the approved-set and package API, and `skillproof sync` (plan, verified install, reversible quarantine). It has been tested on fixtures and dry-run on one real machine: 212 installed skills, 1 approved and matching, 211 never approved, 0 changed. Not yet exercised: `--apply` on a real machine, and the server path against a deployed server. Next: gap 2, then 3, then 4.
