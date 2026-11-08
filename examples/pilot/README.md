# SkillProof pilot benchmark

This is a three-task candidate benchmark for the included evidence-summary skill. It covers factual summary, a source containing an instruction injection, and conflicting source statements. The tasks and rubric are hand-authored and have **not** received independent human review; the manifest labels them accordingly.

Use the OpenAI Responses adapter with explicit agent and grader model IDs. `OPENAI_API_KEY` must be configured locally. The pilot command writes the experiment report plus two human-review files: a blinded sample bundle and a separate unblinding key. Give reviewers only the blind bundle until they finish their annotations.

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
