---
name: log-papercut
description: File a papercut when a skill, tool or flow fights you - a flag it lists but rejects, a command that exits 0 on an error, a lookup that returns nothing when it should match. Use after a second failed attempt, then carry on.
---

# Log a papercut

Use this when a skill you are following gives you trouble that its owner should fix: you tried twice and the
skill's instructions, a tool it names, or its output did not behave as described. File one papercut per problem,
then continue with the task (use a workaround if you found one).

1. Name the skill you were following (its `name` from SKILL.md). Check that it is the skill's name, not the task's.
2. Fill the three fields `--tried` (the exact command or step), `--expected` and `--happened` (the error text or
   the wrong result, copied), one or two sentences each. Check that each field is filled and that no token,
   password, key, personal data or private file content is in it.
3. Run `skillproof papercut --server "$SKILLPROOF_SERVER" --skill NAME --tried "..." --expected "..." --happened "..."
   --fix "..."` (put what would fix it in `--fix`, or leave it out if you do not know). Verify that the command prints
   a `papercut_id`.
4. Tell the user in one line that you filed a papercut for that skill. Confirm your reply names the skill and the
   `papercut_id`, then continue the task.

## Errors

| Failure | Fix |
|---|---|
| `skillproof: command not found` | Tell the user papercuts cannot be filed on this machine (SkillProof is not installed), and continue the task |
| `SKILLPROOF_SERVER` is empty | Ask the user for the SkillProof server address once; if there is none, skip filing and continue |
| HTTP 401 or 403 | The machine has no reporter token: tell the user, include the papercut text in your reply so it is not lost |
| HTTP 422 | A field was empty or too long: shorten the text to under 2,000 characters per field and run step 3 again |
