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

Failed runs are kept out of agreement. An agent failure has no output, so it is never sent to reviewers. A grader failure is sent for review but has no grader score, so it is not paired. Both are counted in the report (`excluded_runs_before_review`, `excluded_annotations`), so you can see how much data a run lost.
