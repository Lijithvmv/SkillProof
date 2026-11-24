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

Gap 1 is built: the package store, the approved-set and package API, and `skillproof sync` (plan, verified install, reversible quarantine). It has been tested on fixtures and dry-run on one real machine: 212 installed skills, 1 approved and matching, 211 never approved, 0 changed. Exercised end to end on copies of four real installed skills (`scripts/sync_e2e.py`, 29 of 29 checks): three
approved through a running server's two-person flow, one copy given an injected instruction and script, one copy missing
a file, and one never-approved skill. A dry run changed nothing. `sync --server ... --apply --strict` reinstalled both drifted skills
from the server's verified packages (fingerprints on disk equal the approved ones). It quarantined the tampered folder and the
unapproved skill intact, with restore records, and a rerun found the machine matching. The real skill folders were
unchanged. One more real finding: a fourth candidate (claude-md-improver) could not enter review, because its instruction quality
scored 51, under the minimum of 60. The same 29 checks, plus 2 more, passed with OIDC sign-in (`--oidc`: every person and the machine signed in through
the code + PKCE flow of the development provider; a call without a token got 401, and a reporter token trying to
register a version got 403): 31 of 31. Not yet exercised: a provider hosted by someone else (Keycloak in production mode on this machine passed; see below), and real (not copied) agent folders.

Gap 2 is built: provenance on every version (human, agent or unknown; agent identities from the token's delegation
claim or an agent OAuth client; declarations only raise the bar). Agent-written and unknown updates are reviewed as new
skills, with the update's own diff kept beside the full review. No author approves its own version, and agent
identities cannot decide, promote, dismiss or change policy. Tested on fixtures, through the API, and on PostgreSQL.
An agent using a person's own token: with OIDC, "a person wrote it" now counts only from a token whose interactive
sign-in (auth_time) is under 15 minutes old; an older or missing sign-in time records the version as unknown, and it
is reviewed as a new skill. Weakest part: an agent acting within minutes of the person signing in, with their token,
still passes as that person. Provenance is only as good as the identities the tenant issues; installed folders stay `unknown`, never
`human`.

Commands: read-only inspection commands are now answered by Python against the workspace (no process starts), so
an agent that looks before it acts sees real output; reading a credential file this way is recorded like read_file.
Everything else is still recorded only.

Gap 3 is built: sandboxed tool runs (`evaluate-skill --sandbox`) with protected-path rules, a canary credential,
trajectories ranked by the capability engine, attribution against baseline runs, and the result in the assurance gate.
First real run (gemma4-e4b, local, 2 tasks x 2 repeats x 2 conditions per skill): the honest release-notes skill gave
decision none (0 rule hits in 8 runs). A version whose SKILL.md asks the agent to send the .env token to a URL and edit
CLAUDE.md gave decision block: canary exfiltration in 4 of 4 skill runs (0 of 4 baseline), CLAUDE.md write refused in
3 of 4 (0 of 4). Its static analysis listed the URL and CLAUDE.md as text; the runs show the agent acting on them.
Weakest part: commands are recorded, never run, so behaviour that depends on command output is not observed; one
local model, two tasks.

Gap 4 is built: `evaluate-skill --load-rate` measures how often the model picks the skill among the installed skills
with the closest descriptions, records it with the experiment, and a citing version gets a LOAD_RATE gate (below
SKILLPROOF_MIN_LOAD_RATE or above SKILLPROOF_MAX_FALSE_LOAD_RATE: not ready). First real run (gemma4-e4b, this
machine, 170 installed skills, the 15 closest as competitors): picked for 6 of 6 relevant requests, 0 of 12 unrelated.
That release-notes run was the easy case: its closest installed competitor had similarity 0.055. Then real rivals
installed on this machine (`skillproof load-rate`, gemma4-e4b, 15 closest competitors, 2 choices per request, requests
written by hand):
- create-pr (rival create-draft-pr, similarity 0.817): 8 of 8 own requests, 0 of 20 sibling or unrelated ones;
- create-draft-pr: 8 of 8, 0 of 20;
- review-security: 3 of 8 (38%), fail. It lost 5 of 8 to claude-security, another installed security skill that the word
  overlap ranked far below the lexically closest rival `review` (0.758). Word overlap misses competitors that say the same thing
  in other words; drawing 15 competitors, not one, is what caught it.
One choice failed because the model answered outside the schema (a fenced `[{"tool": "create-pr"}]`). Such
answers are now read when exactly one listed name appears, and the reasons for any failed choice are kept.
Rivals by meaning are now added: the installed skills that best match the skill's own requests by local embeddings
(nomic-embed-text, request against name and description, as a loader matches), next to the closest descriptions by word overlap.
Comparing description with description did not find claude-security (embeddings ranked it 5th, word overlap 7th); request
matching ranked it 1st, and its word overlap with review-security is 0.06. With 3 competitors, word overlap alone gave
review-security 8 of 8 (a false pass, the real rival absent); with rivals by meaning it measured 4 of 8 (50%, exactly the
default floor, so that run passed; at 15 competitors it measured 3 of 8 and failed). Request matching chooses competitors;
it does not predict the pick (create-pr was outranked on 2 of its 4 requests by it and was still picked 8 of 8).
Requests can now be generated: a local model (qwen2.5-coder, a different model from the gemma4 router) writes the skill's
own requests from its description, and near misses for its three closest rivals. A request that names the skill, copies
four content words in a row, or takes most of its content words from the description is dropped and fed back for up to
three rounds. Generated against hand-written on this machine:
- create-pr: 12 of 12 own, 0 of 12 near misses, against 8 of 8 and 0 of 20. They agree. One round alone dropped all six
  requests, because the description uses the plain task words; feedback rounds fixed that.
- create-draft-pr: 8 of 8, 0 of 10, against 8 of 8, 0 of 20. They agree.
- review-security: 7 of 12 (58%, pass), against 3 of 8 (38%, fail). They disagree on the gate. Both show the loss to
  claude-security, but one generated own request had lost the security angle and went to a general review skill.
  Generated requests can drift from what makes a skill distinct, so they are saved for review and labelled; hand-written
  ones remain the reference.
(The create-draft-pr and review-security generated runs used the first, stricter filter.)
The suggested fix for drift, dropping a request that matches a rival better than the skill, was tested against the data
first and rejected: all four hand-written security requests matched claude-security better than review-security, so it
would have deleted exactly the requests that exposed the real rival. Instead a purpose check judges each written request
against the skill's own description only ("does it ask for what this skill is specifically for?"). On review-security's
requests, gemma4 kept 5 of 6 generated (it dropped the profile-function request) and 4 of 4 hand-written; qwen2.5-coder
also wrongly dropped one genuine security request. With the purpose check on (gemma4 judge), review-security measured
9 of 12 (75%), every miss to claude-security. Hand-written short audit requests gave 3 of 8. Both request styles are
fair, so the rate depends on the mix of requests: the per-request breakdown shows which kinds a rival takes.
Weakest part: the probe is a model choosing from a list, not any agent's loader; thresholds are
starting points in config, not yet in the tenant policy (governance.py is being edited elsewhere).

Closing the weak points (latest round):
- Machines now get their own tokens: `sync` and `fleet-report` use the OAuth client credentials grant (token endpoint
  by OpenID discovery, secret from the environment). The OIDC end-to-end check passed 31 of 31 with sync signing in
  as a registered machine client. A production identity provider is still untested here: none can run on this machine
  without downloading one (Docker and Java are absent), which needs the owner's approval.
- A "human-written" attestation can also require a strong sign-in method (`amr`, e.g. mfa or hwk). Bearer tokens
  remain the limit: an agent holding a fresh, strong token of a person still passes as that person.
- Sandbox: pipelines of read-only commands are emulated, and `>`/`>>` redirects go through the write rules, so
  `echo ... >> CLAUDE.md` is refused and recorded like write_file. Other programs, chaining and substitution are
  still recorded only.
- Purpose check: a second, differently worded judgement was tried and rejected (it accepted the off-purpose request
  too). Three sampled judgements with a majority dropped the off-purpose request (3 of 3) and kept every fair one,
  including the one a single judgement had dropped (1 of 3).
- Load rate: every rate has a 95% interval, the worst request and the rivals that won requests. The two
  review-security runs (3 of 8, 9 of 12) have intervals 14-69% and 47-91%: their disagreement on the gate was noise.
  The gate now passes or fails only when the interval is clear of the threshold, and otherwise asks for more choices.
  Running more choices (review-security, hand-written requests, 5 choices each): 11 of 20 (55%, interval 34-74%),
  still insufficient evidence at a 50% floor; unrelated 0 of 30 (interval 0-11%), clear of the 20% ceiling. The
  breakdown located the problem: "Do a security audit of the current changes" went to claude-security 5 of 5 times
  (its description says "audit"), while the other three requests were picked 3 to 4 times of 5. The useful finding is
  which request type the skill loses, not the average.

Real identity provider: Keycloak 26.8.2 (official release, checksum verified) ran in a separate WSL distro on this
machine, configured by `scripts/keycloak_realm.sh`. Its real tokens broke SkillProof twice, which only a real provider
could show: (1) access tokens are signed with a `JWT` header, not `at+jwt`, so every token was refused; SkillProof now
accepts `JWT` only when configured (`SKILLPROOF_OIDC_ACCEPTED_TYPES`) and only for tokens whose typ claim is Bearer, never an
ID token; (2) people's tokens name the client in `azp`, with no `client_id`; `azp` is now used when `client_id` is absent.
A password-grant token carries no auth_time, so it could never attest that a person wrote a version (the safe
direction); the real browser login (authorization code + PKCE through Keycloak's login page) carries auth_time, and an
upload made that way was recorded as human-written. amr stays empty until Keycloak's login flow is given reference values.
With people signing in through Keycloak's login page and sync signing in as a Keycloak machine client, the end-to-end
check passed 31 of 31.

Production mode and sign-in methods: the same Keycloak then ran in production mode (`kc.sh start`: HTTPS only with a
certificate from a local test CA, PostgreSQL 16 database, strict hostname; `scripts/keycloak_prod_setup.sh`,
`scripts/keycloak_prod_start.sh`), and the realm was rebuilt by `scripts/keycloak_realm.sh`. The browser sign-in's
password step now reports amr `pwd` and its one-time-code step `otp`; erin sets up a TOTP code at her first sign-in (the
script computes RFC 6238 codes, checked against the RFC's test vectors). With the server requiring `otp` for a
human-written attestation, the end-to-end check passed 31 of 31, including: alice (password only) is recorded as
`unknown` with the reason "the sign-in used ['pwd'] ... requires one of ['otp']"; erin's later sign-in with her code
carries ['pwd', 'otp'] and her update is recorded as human-written; the sign-in in which erin set up her code does not
claim `otp`. A trap found on the way: a method reference without a max age is dropped from amr almost at once
(Keycloak's AmrUtils.isAmrValid), so the first attempt showed empty amr after the 30-second code wait; the realm script
now sets `default.reference.maxAge`. Python needs a proper CA (basic constraints and key usage) to trust the server.
Weakest part: still one machine, a test CA and test users; not a hosted provider run by someone else.

Open: a provider hosted and run by someone else; a person's fresh, strong token used by an agent; programs other than
read-only inspection are recorded, not run.
