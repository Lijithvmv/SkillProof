import pytest

from skillproof.activation import NONE, SkillCard, measure_activation, read_skill_card

TARGET = SkillCard("evidence-summary", "Summarize source material with evidence.")
OTHERS = [SkillCard("changelog-writer", "Write release notes."), SkillCard("sql-query-helper", "Write SQL.")]


class ScriptedProbe:
    """Picks the target for requests containing 'summarize', a wrong skill for 'notes', else none."""

    def __init__(self):
        self.positions = []

    def choose(self, *, request, cards):
        self.positions.append([card.name for card in cards].index(TARGET.name))
        if "boom" in request:
            raise RuntimeError("model down")
        if "summarize" in request.lower():
            return TARGET.name
        if "notes" in request:
            return "changelog-writer"
        return NONE


def test_rates_and_expected_lift():
    result = measure_activation(
        target=TARGET, distractors=OTHERS,
        relevant_requests=["Summarize this", "Summarize that", "Turn these notes into an update", "Update please"],
        unrelated_requests=["Write a poem", "Summarize a recipe"],
        probe=ScriptedProbe(), forced_lift_percentage_points=8.0,
    )
    assert result["relevant"]["activation_rate"] == 0.5
    assert result["relevant"]["picked_other_skill"] == 1
    assert result["relevant"]["picked_none"] == 1
    assert result["unrelated"]["false_activation_rate"] == 0.5
    assert result["expected_lift_percentage_points"] == 4.0
    third = result["by_request"][2]
    assert third["target_rate"] == 0.0 and third["choices"] == {"changelog-writer": 1}


def test_failures_are_counted_not_scored_and_positions_vary():
    probe = ScriptedProbe()
    result = measure_activation(
        target=TARGET, distractors=OTHERS, relevant_requests=["Summarize x", "boom"],
        unrelated_requests=[], probe=probe, repeats=6, seed=3,
    )
    assert result["failures"] == 6
    assert result["relevant"]["trials"] == 6
    assert result["relevant"]["activation_rate"] == 1.0
    assert len(set(probe.positions)) > 1  # the target is not always first in the list


def test_unknown_choice_is_a_failure_and_names_must_be_unique():
    class Bad:
        def choose(self, *, request, cards):
            return "made-up-skill"

    result = measure_activation(target=TARGET, distractors=OTHERS, relevant_requests=["x"], unrelated_requests=[], probe=Bad())
    assert result["failures"] == 1 and result["relevant"]["activation_rate"] is None
    with pytest.raises(ValueError):
        measure_activation(target=TARGET, distractors=[TARGET], relevant_requests=["x"], unrelated_requests=[], probe=Bad())


def test_skill_card_reads_frontmatter(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: demo\ndescription: Does a thing. Use when asked.\n---\nBody\n", encoding="utf-8")
    assert read_skill_card(path) == SkillCard("demo", "Does a thing. Use when asked.")
    path.write_text("No frontmatter\n", encoding="utf-8")
    with pytest.raises(ValueError):
        read_skill_card(path)
