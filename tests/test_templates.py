"""Tests built from a skill's own rules. Each test names the decision it changes: which rule gets which test, and
which drafted scenario is allowed to test it."""
import json
import re

from skillproof.checks import run_check
from skillproof.templates import generate_benchmark, template_for


def claim(text, cid="C1"):
    return {"id": cid, "kind": "rule", "text": text, "line": 1}


def passes(template, answer):
    return [run_check(c, answer)[0] for c in template["checks"]]


def test_absence_rule_tests_that_the_answer_flags_and_does_not_supply_the_missing_thing():
    t = template_for(claim("If the requirement cannot be located, flag the NCR as blocking and say what was searched."))
    assert t["shape"] == "absence" and t["thing"] == "requirement"
    good = "No requirement could be found for this finding. Status: BLOCKING. Searched the drawing and the spec library."
    bad = "Requirement: ASME Y14.5, clause 4.2, flatness 0.05 mm. The part fails it."
    assert all(passes(t, good)) and not all(passes(t, bad))
    assert t["verify"]("Operator note: surface looks rough on 12 brackets.") is None
    assert "mentions" in t["verify"]("The requirement for flatness is in the drawing.")  # a scenario that gives it away


def test_never_assert_rule_is_an_absence_test():
    t = template_for(claim("Never asserts a requirement it cannot locate."))
    assert t["shape"] == "absence" and t["thing"] == "requirement"


def test_order_rule_checks_the_order_in_plain_words():
    t = template_for(claim("The order is customer side first, always: installed_at_customer, at_customer, in_transit, finished_goods."))
    assert t["shape"] == "order"
    assert all(passes(t, "Installed at customer: 5. At customer: 10. In transit: 0. Finished goods: 40."))
    assert not all(passes(t, "Finished goods: 40. In transit: 0. At customer: 10. Installed at customer: 5."))
    assert "in transit" in t["verify"]("50 parts installed at customer, 10 at customer, 40 in finished goods.")


def test_never_write_uses_specific_phrases_only():
    t = template_for(claim('The row reads "not checked" and never "0 parts".'))
    assert t["shape"] == "never_write" and [c.value for c in t["checks"]] == ["0 parts"]
    assert template_for(claim('Never "shared," never "posted."')) is None  # one common word is not a test


def test_always_state_and_uncovered_rules():
    t = template_for(claim("Always state the assumption behind the downtime rate."))
    assert t["shape"] == "always_state" and all(passes(t, "Assumption: 8 h shifts.")) and not all(passes(t, "Downtime 12%."))
    assert template_for(claim("Prefer short sentences in every reply.")) is None


def test_generated_scenario_that_gives_away_the_missing_thing_is_redrafted():
    # Decision: a background that contains what the rule says is missing never becomes a test.
    claims = {"skill": "ncr", "description": "Writes NCRs.", "triggers": ["raise an NCR"],
              "claims": [claim("If the requirement cannot be located, flag the NCR as blocking and say what was searched.")]}
    replies = iter([{"request": "Raise an NCR", "context": "Requirement: flatness 0.05 mm per drawing."},
                    {"request": "Raise an NCR for these brackets", "context": "Operator: 12 brackets look rough. No measurement."}])
    result = generate_benchmark("", claims, lambda prompt, schema: json.dumps(next(replies)), tasks=1)
    [task] = result["tasks"]
    assert task.context.startswith("Operator") and result["rejected"][0]["reason"].startswith("the background mentions")
    assert re.search(task.checks[1].value, "Status: blocking")
