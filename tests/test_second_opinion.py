"""The local model's second opinion lowers mentions one level on safe categories and never hides anything."""
import pytest

from skillproof.capabilities import build_manifest, diff_manifests
from skillproof.second_opinion import SAFE_CATEGORIES, ollama_asker, second_opinions
from skillproof.triage import triage

OLD = {"SKILL.md": b"---\nname: s\ndescription: d\n---\n# s\n"}
NEW = {**OLD, "scripts/run.py": b"import subprocess\nsubprocess.run(['git', 'status'])\n",
       "references/notes.md": b"```bash\ncurl -s https://api.example-team.dev/v1/items\n```\n"}


def test_mentions_are_lowered_never_hidden_and_hosts_are_not_asked():
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return "MENTION"

    new = build_manifest(NEW)
    new["second_opinion"] = second_opinions(new, NEW, ask)
    assert set(new["second_opinion"]) == {"process_execution|subprocess"}  # hosts are not in the safe set
    assert all("<evidence>" in p and ">> " in p for p in asked)
    items = {(i["category"], i["value"]): i for i in triage(diff_manifests(build_manifest(OLD), new), new_manifest=new)["items"]}
    lowered = items[("process_execution", "subprocess")]
    plain = triage(diff_manifests(build_manifest(OLD), build_manifest(NEW)), new_manifest=build_manifest(NEW))["items"]
    before = {(i["category"], i["value"]): i["level"] for i in plain}[("process_execution", "subprocess")]
    assert lowered["second_opinion"] == "likely_mention" and lowered["level"] == {"block": "ask", "ask": "note", "note": "note"}[before]
    assert ("network_hosts", "api.example-team.dev") in items  # still raised at its own level


def test_model_must_be_local_and_failures_keep_the_level():
    with pytest.raises(ValueError, match="loopback"):
        ollama_asker(url="http://models.example.org:11434")

    def broken(prompt):
        raise OSError("model down")

    assert second_opinions(build_manifest(NEW), NEW, broken) == {}
    assert "network_hosts" not in SAFE_CATEGORIES and "package_installs" not in SAFE_CATEGORIES
