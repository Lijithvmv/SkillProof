"""Generated load-rate requests: written from descriptions, refused when they name the skill or copy its description,
and near misses written for the closest rivals. Each test names the decision it guards."""
import json
from types import SimpleNamespace

from skillproof.cli import evaluation as cli_evaluation
from skillproof.engines.requests import check, copies, write_requests

DESCRIPTION = "Create a pull request for the current session. Use when the user wants to open a PR with the session's changes."


# Decision: a generated request that names the skill, copies four content words in a row from its description, takes
# most of its content words from it, repeats another, or is empty is not used; a paraphrase, or the natural phrase for
# the task ("create a pull request") in the user's own sentence, is.
def test_generated_requests_that_echo_the_description_are_dropped():
    seen = {"ship my branch so the team can review it"}
    assert check("Use create-pr to ship this", "create-pr", DESCRIPTION, set()) == "names the skill"
    assert check("I want a PR, use create pr", "create-pr", DESCRIPTION, set()) == "names the skill"
    assert copies("Please create a pull request for the current work", DESCRIPTION) == "create pull request current"
    assert check("I want to create a pull request for the changes I made to the feature branch.", "create-pr", DESCRIPTION, set()) is None
    assert check("Please create a pull request for the latest modifications in our current work session.", "create-pr",
                 DESCRIPTION, set()).startswith("mostly the description's words")
    assert check("please create a pull request for the current session", "create-pr", DESCRIPTION, set()).startswith("copies")
    assert check("Ship my branch so the team can review it.", "create-pr", DESCRIPTION, seen) == "duplicate"
    assert check("", "create-pr", DESCRIPTION, set()) and check("x" * 301, "create-pr", DESCRIPTION, set())
    assert check("My feature is finished, get it in front of reviewers.", "create-pr", DESCRIPTION, set()) is None

    def ask(prompt, schema):
        return json.dumps({"requests": ["Use create-pr now.", "My feature is done, send it for review.",
                                        "My feature is done, send it for review.", "Open a PR with the session's changes please."]})

    kept, dropped = write_requests("create-pr", DESCRIPTION, ask, 4, rounds=1)
    assert kept == ["My feature is done, send it for review."]
    assert sorted(d["reason"].split(" (")[0] for d in dropped) == ["copies the description", "duplicate", "names the skill"]


def card(folder, name, description):
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n\nBody.\n", encoding="utf-8")


# Decision: without hand-written requests, load-rate writes the skill's own requests from its description and near
# misses for its closest rival (by request match), counts the near misses as requests it must not take, and keeps
# everything it wrote and dropped in the result for review.
def test_load_rate_generates_own_requests_and_near_misses(tmp_path, monkeypatch):
    import skillproof.adapters.ollama as ollama

    root = tmp_path / "skills"
    card(root / "draft", "create-draft-pr", "Create a draft pull request. Use when the work is not finished.")
    card(root / "pptx", "pptx", "Make slide decks.")
    skill = tmp_path / "create-pr"
    card(skill, "create-pr", "Create a pull request. Use when the user wants to open a PR.")
    written = {"create-pr": ["My feature is finished, get it reviewed.", "Use create-pr please.", "Send my branch to the team for merging."],
               "create-draft-pr": ["I'm halfway done, share it early without merging.", "Show my unfinished branch to others."]}

    def asker(model, url, **kwargs):
        return lambda prompt, schema: json.dumps({"requests": written[prompt.split("Tool name: ")[1].split("\n")[0]]})

    class Embedder:
        def __init__(self, **kwargs):
            pass

        def embed(self, texts, prefix=""):
            return [[1.0, 0.0] if ("draft" in t or "finish" in t or "branch" in t) else [0.0, 1.0] for t in texts]

    class Probe:
        def __init__(self, **kwargs):
            pass

        def choose(self, *, request, cards):
            return "create-draft-pr" if ("halfway" in request or "unfinished" in request) else "create-pr"

    monkeypatch.setattr(ollama, "ollama_json_asker", asker)
    monkeypatch.setattr(ollama, "OllamaEmbedder", Embedder)
    monkeypatch.setattr(cli_evaluation, "OllamaActivationProbe", Probe)
    args = SimpleNamespace(skill=str(skill), requests=None, unrelated_tasks=None, competitors_root=[str(root)], competitors=2,
                           distractor_skills=None, model="m", ollama_url="http://127.0.0.1:11434", seed=0, load_repeats=1,
                           embed_model="e", generate=3, near_misses=None, rivals=1, generator_model=None)
    result, code = cli_evaluation.run_load_rate(args)
    requests = result["requests"]
    assert requests["source"] == "generated_from_descriptions"
    assert requests["relevant"] == ["My feature is finished, get it reviewed.", "Send my branch to the team for merging."]
    reasons = [d["reason"] for d in requests["dropped"]]
    assert reasons[0] == "names the skill" and set(reasons) == {"names the skill", "duplicate"}  # later rounds repeat
    assert {n["rival"] for n in requests["near_misses"]} == {"create-draft-pr"} and len(requests["near_misses"]) == 2
    assert result["relevant"]["activation_rate"] == 1.0 and result["unrelated"]["trials"] == 2
    assert result["unrelated"]["false_activation_rate"] == 0.0 and code == 0


# Decision: rejected requests go back to the model with the reason, so a description in plain task words still gets
# usable requests on a later round.
def test_rejected_requests_are_fed_back():
    prompts = []

    def ask(prompt, schema):
        prompts.append(prompt)
        if len(prompts) == 1:
            return json.dumps({"requests": ["Open a PR with the session's changes."]})
        return json.dumps({"requests": ["My feature is done, send it to the team for review."]})

    kept, dropped = write_requests("create-pr", DESCRIPTION, ask, 1)
    assert kept == ["My feature is done, send it to the team for review."] and len(prompts) == 2
    assert "rejected: copies the description" in prompts[1] and "Open a PR with the session's changes." in prompts[1]
