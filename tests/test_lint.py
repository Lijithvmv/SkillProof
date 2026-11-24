"""Structural lint checks: each test names the decision the check makes."""
from skillproof.engines.analyzer import analyze_files
from skillproof.engines.lint import lint_skill

GOOD = """# Release notes

1. Run `python3 scripts/collect.py CHANGES.txt`. Check that it prints one line per change.
2. Write the notes to `RELEASE_NOTES.md`. Verify that every issue number from step 1 appears.
3. Show the notes. Confirm the user can see both sections.

## Errors

| Failure | Fix |
|---|---|
| collect.py exits 2 (no CHANGES.txt) | Ask the user where the changes are listed |
| An issue number is missing | Re-read CHANGES.txt and add it under Fixes |
"""


def status(result, code):
    return next(c for c in result["checks"] if c["code"] == code)


# Decision: a skill laid out the way an agent can follow it (numbered steps, each checked, concrete commands, a real
# error-recovery table, files present) passes every check.
def test_a_well_structured_skill_passes():
    result = lint_skill(GOOD, {"description": "Write release notes from CHANGES.txt."}, {"SKILL.md": GOOD, "scripts/collect.py": "print()"})
    assert result["failed"] == 0, [c for c in result["checks"] if c["status"] == "fail"]


# Decision: a step with no way to check it, a recovery row whose fix is "try again", and a body that points to a script
# the package does not ship each fail, with the line a reviewer must read.
def test_unchecked_steps_weak_fixes_and_missing_files_fail():
    body = GOOD.replace(" Check that it prints one line per change.", "").replace("Re-read CHANGES.txt and add it under Fixes", "Try again")
    result = lint_skill(body, {"description": "Write release notes."}, {"SKILL.md": body})
    assert status(result, "STEP_VERIFIED")["status"] == "fail" and "body line 3" in status(result, "STEP_VERIFIED")["evidence"][0]
    assert status(result, "ERROR_TABLE")["status"] == "fail"
    assert status(result, "FILES_EXIST")["evidence"] == ["body line 3: scripts/collect.py"]


# Decision: a path the skill teaches as an example is not a file it uses, so a skill about writing skills is not failed
# for the example scripts it names.
def test_example_paths_are_not_required_files():
    body = "Example: when building a PDF skill, the analysis shows:\n\n1. A `scripts/rotate_pdf.py` script would help\n"
    assert status(lint_skill(body, {"description": "x"}, {"SKILL.md": body}), "FILES_EXIST")["status"] == "pass"


# Decision: a package that installs a tool server fails (every tool's definition would load into every session), and a
# long always-loaded description fails the budget.
def test_tool_servers_and_long_descriptions_fail():
    result = lint_skill(GOOD, {"description": "word " * 200}, {"SKILL.md": GOOD, "scripts/collect.py": "", ".mcp.json": "{}"})
    assert status(result, "NO_TOOL_SERVER")["status"] == "fail"
    assert status(result, "DESCRIPTION_BUDGET")["status"] == "fail"


# Decision: every analysis report carries the lint result, read with paths relative to the skill's own folder.
def test_analysis_reports_include_lint():
    skill = "---\nname: notes\ndescription: Write release notes.\n---\n" + GOOD
    report = analyze_files({"notes/SKILL.md": skill, "notes/scripts/collect.py": "print()"})
    assert report["lint"]["failed"] == 0 and status(report["lint"], "FILES_EXIST")["status"] == "pass"
