from skillproof.compatibility import analyze_model_compatibility


def _records(provider, model, base, enabled):
    rows = []
    for index, (before, after) in enumerate(zip(base, enabled), 1):
        trial_id = f"task:{index}"
        rows.extend([
            {"provider": provider, "model": model, "condition": "baseline", "trial_id": trial_id, "score": before},
            {"provider": provider, "model": model, "condition": "skill_enabled", "trial_id": trial_id, "score": after},
        ])
    return rows


def test_compares_paired_lift_across_models_and_flags_regression():
    records = _records("provider-x", "model-a", [0.5, 0.6, 0.7], [0.7, 0.8, 0.9])
    records += _records("provider-y", "model-b", [0.7, 0.8, 0.9], [0.6, 0.7, 0.8])
    report = analyze_model_compatibility(records)
    assert report["measured_model_count"] == 2
    assert report["lift_spread_percentage_points"] == 30.0
    assert {item["code"] for item in report["findings"]} == {"SKILL_REGRESSION_ON_MODEL", "MODEL_SENSITIVE_SKILL_LIFT"}
    model_b = next(item for item in report["models"] if item["model"] == "model-b")
    assert model_b["skill_lift_percentage_points"] == -10.0
    assert model_b["assessment"] == "measured"


def test_small_or_unpaired_samples_are_not_marked_measured():
    records = [
        {"provider": "p", "model": "m", "condition": "baseline", "trial_id": "a", "score": 0.5},
        {"provider": "p", "model": "m", "condition": "skill_enabled", "trial_id": "b", "score": 0.7},
    ]
    report = analyze_model_compatibility(records, minimum_pairs=2)
    assert report["models"][0]["assessment"] == "insufficient_data"
    assert report["models"][0]["skill_lift_percentage_points"] is None

