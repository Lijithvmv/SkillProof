from skillproof.analyzer import analyze_files


VALID = """---
name: demo-skill
description: A small demonstration skill. Use when testing the analyzer.
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


def _skill(frontmatter: str, body: str = "Do the thing.\n", extra=None):
    from skillproof.analyzer import analyze_files
    files = {"demo/SKILL.md": f"---\n{frontmatter}\n---\n{body}"}
    files.update(extra or {})
    return {f["code"] for f in analyze_files(files)["findings"]}


def test_anthropic_metadata_rules():
    codes = _skill("name: claude-helper\ndescription: I can help you with <b>files</b>.")
    assert {"NAME_RESERVED_WORD", "METADATA_XML_TAG", "DESCRIPTION_NO_WHEN", "DESCRIPTION_NOT_THIRD_PERSON"} <= codes
    good = _skill("name: demo\ndescription: Processes CSV files into reports. Use when the user supplies a CSV.")
    assert not {"NAME_RESERVED_WORD", "METADATA_XML_TAG", "DESCRIPTION_NO_WHEN", "DESCRIPTION_NOT_THIRD_PERSON"} & good


def test_reference_depth_toc_and_windows_paths():
    long_ref = "# Guide\n" + "line\n" * 120 + "See [more](deeper.md).\n"
    codes = _skill(
        "name: demo\ndescription: Does a thing. Use when asked.",
        body=r"Read [guide](guide.md). Run scripts\build.py." + "\n",
        extra={"demo/guide.md": long_ref, "demo/deeper.md": "# Deeper\n"},
    )
    assert {"REFERENCE_TOO_DEEP", "REFERENCE_NO_TOC", "WINDOWS_PATH"} <= codes
    with_toc = "# Guide\n## Contents\n- [A](#a)\n" + "line\n" * 120
    codes = _skill("name: demo\ndescription: Does a thing. Use when asked.", body="Read [guide](guide.md).\n", extra={"demo/guide.md": with_toc})
    assert not {"REFERENCE_TOO_DEEP", "REFERENCE_NO_TOC", "WINDOWS_PATH"} & codes
