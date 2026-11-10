# SkillProof pilot benchmark

This is a three-task candidate benchmark for the included evidence-summary skill. It covers factual summary, a source containing an instruction injection, and conflicting source statements. The tasks and rubric are hand-authored and have **not** received independent human review; the manifest labels them accordingly.

You can run the pilot on a local [Ollama](https://ollama.com) server with no account or API key:

```powershell
skillproof pilot --provider ollama `
  --model gemma4-e4b-ctx8k:latest `
  --grader-model qwen2.5-coder-7b-ctx8k:latest `
  --skill-file examples/pilot/skill.md `
  --benchmark examples/pilot/benchmark.jsonl `
  --repeats 1 `
  --output pilot-report.json `
  --review-output review/blinded-samples.json `
  --unblinding-key-output review/unblinding-key.json
```

Use any models you have pulled. A grader that differs from the agent model avoids a model grading its own answers. The Ollama adapter only connects to a loopback address (`--ollama-url`, default `http://127.0.0.1:11434`), so task text and outputs stay on your machine. The agent samples at `--temperature 0.7` with one seed per call taken from `--seed`: rerunning with the same seed and models reproduces the run, and repeats of one task still differ. The grader always uses temperature 0 and a JSON schema. Small local models are slow (minutes per call on a laptop CPU) and grade less reliably than large hosted models, so check the grader against human scores before trusting it.

### Load rate: is the skill picked when it is not forced?

The paired run pastes the skill in, so its lift is the gain *when the skill is used*. Add `--distractor-skills examples/pilot/distractor-skills.jsonl --unrelated-tasks examples/pilot/unrelated-tasks.jsonl` (Ollama only for now) and the report gets an `activation` section: the agent model sees the skill's name and description among the distractors, in shuffled order, and chooses one skill or `none` for each benchmark prompt and each unrelated prompt.

- `relevant.activation_rate`: share of benchmark prompts where it picked this skill.
- `unrelated.false_activation_rate`: share of unrelated prompts where it picked this skill anyway.
- `expected_lift_percentage_points`: activation rate × the forced lift.
- `by_request`: the rate and the choices for each prompt. Read this first: an average can hide a task where the skill is never picked because another skill's description fits it better.

Seeds reduce but do not remove run-to-run variation in local models, and thinking models need a token budget large enough to finish reasoning before they answer.

This is a proxy: a model choosing from a list is not any specific agent's loader. Use it to compare descriptions or versions of one skill, not to predict one product's behaviour. Three of the example distractors are deliberately close to the benchmark tasks (release notes, customer replies, status reports).

Or use the OpenAI Responses adapter with explicit agent and grader model IDs. `OPENAI_API_KEY` must be configured locally. The pilot command writes the experiment report plus two human-review files: a blinded sample bundle and a separate unblinding key. Give reviewers only the blind bundle until they finish their annotations.

Example after installing the optional `openai` extra:

```powershell
$env:SKILLPROOF_OPENAI_MODEL = "your-agent-model-id"
$env:SKILLPROOF_OPENAI_GRADER_MODEL = "your-grader-model-id"
skillproof pilot `
  --skill-file examples/pilot/skill.md `
  --benchmark examples/pilot/benchmark.jsonl `
  --repeats 2 `
  --output pilot-report.json `
  --review-output review/blinded-samples.json `
  --unblinding-key-output review/unblinding-key.json
```

After a separate reviewer scores the samples, merge the completed annotations with the unblinding key using `skillproof grader-agreement`. The resulting report includes score error, threshold agreement, Cohen's kappa, and results by condition after unblinding. It describes agreement; it does not validate the benchmark or certify the grader.

### More than one reviewer

Give each reviewer their own copy of the blind bundle and annotation template, and ask them to put their own `reviewer_id` on every row. Rows still at `"human_score": null` are skipped. Then pass every file:

```powershell
skillproof grader-agreement review/reviewer-1.json review/unblinding-key.json `
  --extra-annotations review/reviewer-2.jsonl `
  --output agreement-report.json
```

The grader is compared with the mean of the reviewers' scores, and with each reviewer separately (`grader_vs_each_reviewer`). When at least two reviewers scored the same samples, `human_agreement` gives:

- `pairwise`: agreement and Cohen's kappa for each pair of reviewers.
- `krippendorff_alpha.humans_only` and `krippendorff_alpha.humans_plus_grader`: alpha on the same samples, first with reviewers only, then with the grader added as one more rater. If adding the grader lowers alpha, the grader disagrees with the reviewers more than they disagree with each other. If alpha stays about the same, the grader is within the range of human disagreement.

With one reviewer, `human_agreement.status` is `not_measured`: there is no human baseline to judge the grader against.

Small samples: this pilot produces at most 12 samples (3 tasks × 2 repeats × 2 conditions). Kappa and alpha from that few samples can move a lot when one label changes. Read them as a first check, not a result.

Failed runs are kept out of agreement. An agent failure has no output, so it is never sent to reviewers. A grader failure is sent for review but has no grader score, so it is not paired. Both are counted in the report (`excluded_runs_before_review`, `excluded_annotations`), so you can see how much data a run lost.
