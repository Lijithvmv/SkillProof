"""Pass-or-fail structural checks for a skill package: how well an agent can follow it, and what it costs to carry.

The instruction-quality heuristics (semantic.py) look for cue words anywhere in the text. These checks look at the
structure an agent actually follows, step by step, and at the package as a whole:

- STEPS_NUMBERED      a skill with several actions lays them out as numbered steps;
- STEP_VERIFIED       every numbered step says how to check that it worked before the next one;
- STEP_CONCRETE       in a technical skill, every numbered step names a concrete command, file or call;
- ERROR_TABLE         the skill has an error-recovery table (a failure and its fix per row); "try again" is no fix;
- BODY_LENGTH         the body an agent loads when the skill runs stays under 500 lines;
- DESCRIPTION_BUDGET  the description, which every session loads for every installed skill, stays short;
- FILES_EXIST         every file the body points to (scripts/, references/, a relative path) is in the package;
- NO_TOOL_SERVER      the package does not install a tool server (.mcp.json): it would load every tool's definition
                      into every session and run code outside the skill's review.

Each check passes, fails, or does not apply, with the evidence (line numbers) a reviewer needs. Not a model's opinion.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

STEP = re.compile(r"^\s{0,3}(\d+)[.)]\s+(.*)$")
ACTION = re.compile(r"\b(use|open|read|write|create|generate|run|execute|check|verify|validate|test|review|compare|save|return|"
                    r"provide|ask|install|configure|inspect|summari[sz]e|transform|delete|update|build|deploy|call|query|fetch|"
                    r"commit|push|merge|send|list|find|search|copy|move|edit|add|remove|set|record|upload|download)\b", re.I)
VERIFY = re.compile(r"\b(verify|validate|confirm|check(?:s|ing)?\s+(?:that|the|it|whether|for)|make sure|ensure|expect(?:ed)?|"
                    r"should (?:show|return|print|see|exit|contain|pass)|must (?:show|return|pass|exit)|assert|exits? (?:with )?0|"
                    r"succeeds?|passes|is non-?empty|returns? (?:no|an?|the)|look for)\b", re.I)
CONCRETE = re.compile(r"`[^`]+`|```|\b[\w./-]+\.(?:py|sh|js|ts|json|ya?ml|md|sql|toml|txt|csv)\b|\b(?:https?://)\S+")
TECHNICAL = re.compile(r"\b(command|script|cli|terminal|shell|api|endpoint|query|sql|git|npm|pip|python|node|docker|kubectl|"
                       r"curl|run|execute|deploy|install|build)\b", re.I)
RECOVERY_HEADING = re.compile(r"^#{1,6}\s+.*\b(error|errors|troubleshoot\w*|recover\w*|failure|failures|when .*fails|problems|"
                              r"common issues|if something goes wrong)\b", re.I)
WEAK_FIX = re.compile(r"^\s*(?:try again|retry|re-?run( it)?|run again|repeat|start over)[.!]?\s*$", re.I)
PATH_REF = re.compile(r"(?<![\w/.-])((?:\.{1,2}/)?(?:scripts|references|reference|assets|templates|bin|tools|examples|docs)/"
                      r"[\w./-]+\.[A-Za-z0-9]{1,6})\b")
EXAMPLE = re.compile(r"\b(e\.g\.|for example|for instance|such as)|\bexamples?\b\s*\**\s*:", re.I)
MAX_BODY_LINES = 500
MAX_DESCRIPTION_TOKENS = 120   # about four characters per token; the name and description load in every session


def _check(code: str, status: str, message: str, evidence: list[str] | None = None) -> dict[str, Any]:
    return {"code": code, "status": status, "message": message, "evidence": (evidence or [])[:8]}


def _steps(lines: list[str]) -> list[tuple[int, str, list[str]]]:
    """Numbered steps outside code fences: (line number, text, the lines up to the next step or heading)."""
    steps: list[tuple[int, str, list[str]]] = []
    in_fence = False
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            if steps:
                steps[-1][2].append(raw)
            continue
        match = None if in_fence else STEP.match(raw)
        if match:
            steps.append((number, match.group(2).strip(), [match.group(2)]))
        elif steps and (in_fence or (stripped and not stripped.startswith("#"))):
            steps[-1][2].append(raw)
        elif steps and stripped.startswith("#"):
            steps.append((0, "", []))  # a heading ends the step it follows
    return [s for s in steps if s[0]]


def _tables_after_recovery_heading(lines: list[str]) -> tuple[int | None, list[list[str]]]:
    """The first error-recovery heading and the rows of the table under it (before the next heading)."""
    for index, raw in enumerate(lines):
        if RECOVERY_HEADING.match(raw.strip()):
            rows = []
            for line in lines[index + 1:]:
                stripped = line.strip()
                if stripped.startswith("#"):
                    break
                if stripped.startswith("|") and not re.fullmatch(r"\|?[\s:|-]+\|?", stripped):
                    rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
            return index + 1, rows[1:] if rows else []  # the first row is the header
    return None, []


def lint_skill(body: str, metadata: dict[str, Any] | None, files: dict[str, str]) -> dict[str, Any]:
    """Run every check on a SKILL.md body, its frontmatter and the package's files (paths relative to the skill root)."""
    lines = body.splitlines()
    checks: list[dict[str, Any]] = []
    prose = [(n, line) for n, line in enumerate(lines, 1) if line.strip() and not line.strip().startswith(("#", "```", "|", ">"))]
    actions = [(n, line) for n, line in prose if ACTION.search(line)]
    steps = _steps(lines)

    if len(actions) >= 3 and len(steps) < 2:
        checks.append(_check("STEPS_NUMBERED", "fail", "The skill has several actions but no numbered steps to follow in order.",
                             [f"body line {n}: {line.strip()[:120]}" for n, line in actions[:4]]))
    elif len(steps) >= 2:
        checks.append(_check("STEPS_NUMBERED", "pass", f"{len(steps)} numbered steps."))
    else:
        checks.append(_check("STEPS_NUMBERED", "n/a", "Fewer than three actions: a sequence is not needed."))

    if steps:
        unverified = [(n, text) for n, text, block in steps if not VERIFY.search("\n".join(block))]
        checks.append(_check("STEP_VERIFIED", "fail" if unverified else "pass",
                             f"{len(unverified)} of {len(steps)} steps give no way to check that they worked." if unverified
                             else "Every step says how to check its result.",
                             [f"step at body line {n}: {text[:120]}" for n, text in unverified]))
        technical = bool(TECHNICAL.search(body))
        if technical:
            vague = [(n, text) for n, text, block in steps if ACTION.search(text) and not CONCRETE.search("\n".join(block))]
            checks.append(_check("STEP_CONCRETE", "fail" if vague else "pass",
                                 f"{len(vague)} steps name no concrete command, file or call." if vague
                                 else "Every step names something concrete to run or open.",
                                 [f"step at body line {n}: {text[:120]}" for n, text in vague]))
        else:
            checks.append(_check("STEP_CONCRETE", "n/a", "Not a technical skill."))
    else:
        checks.append(_check("STEP_VERIFIED", "n/a", "No numbered steps."))
        checks.append(_check("STEP_CONCRETE", "n/a", "No numbered steps."))

    heading_line, rows = _tables_after_recovery_heading(lines)
    if max(len(actions), len(steps)) < 3:
        checks.append(_check("ERROR_TABLE", "n/a", "Fewer than three actions."))
    elif heading_line is None or not rows:
        checks.append(_check("ERROR_TABLE", "fail", "No error-recovery table (a heading such as 'Errors' or 'Troubleshooting' "
                             "with a table of failures and fixes).", [f"body line {heading_line}: heading without a table"] if heading_line else []))
    else:
        weak = [row for row in rows if len(row) < 2 or not row[-1] or WEAK_FIX.match(row[-1])]
        checks.append(_check("ERROR_TABLE", "fail" if weak else "pass",
                             f"{len(weak)} of {len(rows)} rows give no real fix ('try again' is not one)." if weak
                             else f"Error-recovery table with {len(rows)} failures and fixes.",
                             [" | ".join(row)[:120] for row in weak]))

    count = len(lines)
    checks.append(_check("BODY_LENGTH", "fail" if count > MAX_BODY_LINES else "pass",
                         f"The body is {count} lines; keep it under {MAX_BODY_LINES} and move detail to reference files."
                         if count > MAX_BODY_LINES else f"{count} lines."))

    description = str((metadata or {}).get("description") or "")
    tokens = (len(description) + 3) // 4
    if not description:
        checks.append(_check("DESCRIPTION_BUDGET", "fail", "No description: the agent cannot tell when to use the skill."))
    else:
        checks.append(_check("DESCRIPTION_BUDGET", "fail" if tokens > MAX_DESCRIPTION_TOKENS else "pass",
                             f"The description is about {tokens} tokens, loaded in every session for every installed skill; "
                             f"keep it under {MAX_DESCRIPTION_TOKENS}." if tokens > MAX_DESCRIPTION_TOKENS else f"About {tokens} tokens."))

    names = {re.sub(r"^(?:\./|/)+", "", PurePosixPath(p).as_posix()) for p in files}
    missing = []
    in_example = False
    for n, line in enumerate(lines, 1):
        # A path the skill teaches as an example is not a file it uses. An example runs from a line that introduces one
        # ("Example:", "e.g.") through the list under it, until the next heading or ordinary paragraph.
        stripped = line.strip()
        if stripped.startswith("#"):
            in_example = False
        elif stripped and not re.match(r"([-*+]|\d+[.)])\s", stripped):
            in_example = bool(EXAMPLE.search(stripped))
        if in_example or EXAMPLE.search(line):
            continue
        for ref in PATH_REF.findall(line):
            clean = PurePosixPath(re.sub(r"^(?:\./)+", "", ref)).as_posix()
            if clean not in names and f"skill/{clean}" not in names and (n, clean) not in missing:
                missing.append((n, clean))
    checks.append(_check("FILES_EXIST", "fail" if missing else "pass",
                         f"{len(missing)} referenced files are not in the package." if missing else "Every referenced file is in the package.",
                         [f"body line {n}: {ref}" for n, ref in missing]))

    servers = sorted(p for p in names if PurePosixPath(p).name == ".mcp.json")
    checks.append(_check("NO_TOOL_SERVER", "fail" if servers else "pass",
                         "The package installs a tool server; every tool's definition would load into every session." if servers
                         else "No tool server in the package.", servers))

    applied = [c for c in checks if c["status"] != "n/a"]
    return {"method": "structural_checks", "passed": sum(c["status"] == "pass" for c in applied),
            "failed": sum(c["status"] == "fail" for c in applied), "checks": checks}
