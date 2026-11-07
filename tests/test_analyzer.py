from skillproof.analyzer import analyze_files


VALID = """---
name: demo-skill
description: A small demonstration skill.
---
# Instructions
Read [the guide](references/guide.md).
"""


def test_valid_skill_builds_fingerprint_graph_and_metrics():
    report = analyze_files({
        "demo-skill/SKILL.md": VALID,
        "demo-skill/references/guide.md": "# Guide\nFollow these steps.\n",
    })
    assert len(report["package_fingerprint"]) == 64
    assert report["reference_graph"]["demo-skill/SKILL.md"] == ["demo-skill/references/guide.md"]
    assert report["progressive_disclosure"]["linked_supporting_file_count"] == 1
    assert not report["findings"]


def test_duplicate_frontmatter_keys_are_reported():
    report = analyze_files({"demo-skill/SKILL.md": "---\nname: first\nname: second\ndescription: demo\n---\n"})
    assert any(item["code"] == "YAML_DUPLICATE_KEY" for item in report["findings"])


def test_invalid_metadata_type_and_broken_reference_are_reported():
    content = "---\nname: [not, a, string]\ndescription: demo\n---\nSee [missing](missing.md).\n"
    report = analyze_files({"demo-skill/SKILL.md": content})
    codes = {item["code"] for item in report["findings"]}
    assert "METADATA_NAME_TYPE" in codes
    assert "BROKEN_REFERENCE" in codes


def test_missing_skill_file_is_reported():
    report = analyze_files({"notes.md": "Nothing here."})
    assert report["findings"][0]["code"] == "SKILL_MISSING"
