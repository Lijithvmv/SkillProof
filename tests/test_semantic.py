from skillproof.semantic import analyze_instructions


def test_detects_vagueness_and_missing_quality_controls():
    report = analyze_instructions("Generate production-ready code as needed.")
    codes = {item["code"] for item in report["findings"]}
    assert "VAGUE_INSTRUCTION" in codes
    assert "VERIFICATION_STEP_MISSING" in codes
    assert "ERROR_RECOVERY_UNSPECIFIED" in codes
    assert report["method"] == "deterministic_heuristics"


def test_covers_explicit_workflow_quality_signals():
    report = analyze_instructions("""First, install the package and check credentials.
Then create the Python script and return the output as JSON.
Finally, run tests and verify the result. If a command fails, report the error and retry once.
""")
    assert report["coverage"] == {
        "actionable_steps": True,
        "prerequisites": True,
        "output_expectations": True,
        "verification": True,
        "error_recovery": True,
    }
    assert not report["findings"]


def test_possible_direct_conflict_is_evidence_backed():
    report = analyze_instructions("Always use the default database.\nNever use the default database.")
    finding = next(item for item in report["findings"] if item["code"] == "POSSIBLE_INSTRUCTION_CONFLICT")
    assert "Always use" in finding["evidence"]
    assert "Never use" in finding["evidence"]


def test_analyzer_exposes_semantic_report():
    from skillproof.analyzer import analyze_files

    report = analyze_files({"sample/SKILL.md": "---\nname: sample\ndescription: sample skill\n---\nCreate code.\n"})
    assert report["schema_version"] == "1.7.0"
    assert report["instruction_quality"]["instruction_count"] == 1
