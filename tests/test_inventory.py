from skillproof.cli import main
from skillproof.inventory import inventory


def make(root, folder, name, description, body="Do it.\n"):
    path = root / folder
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n{body}", encoding="utf-8")


def test_duplicates_are_split_into_identical_and_divergent(tmp_path):
    make(tmp_path, "a/pdf-tools", "pdf-tools", "Fill PDF forms. Use when asked.")
    make(tmp_path, "b/pdf-tools", "pdf-tools", "Fill PDF forms. Use when asked.")
    make(tmp_path, "a/notes", "notes", "Summarize notes. Use when asked.")
    make(tmp_path, "b/notes", "notes", "Summarize notes. Use when asked.", body="Different body.\n")
    result = inventory([tmp_path])
    status = {item["name"]: item["status"] for item in result["duplicate_names"]}
    assert status == {"pdf-tools": "identical", "notes": "divergent"}
    assert result["divergent_duplicates"] == 1
    assert main(["inventory", str(tmp_path), "--output", str(tmp_path / "out.json")]) == 1


def test_competing_descriptions_are_reported_once_per_pair(tmp_path):
    make(tmp_path, "x/browser-pane", "browser-pane", "Drive the built-in browser pane: tabs, sign-ins, page reading.")
    make(tmp_path, "x/chrome-ext", "chrome-ext", "Drive the Chrome browser extension: tabs, sign-ins, page reading.")
    make(tmp_path, "x/sql", "sql", "Write and explain PostgreSQL queries.")
    make(tmp_path, "y/sql", "sql", "Write and explain PostgreSQL queries.")
    result = inventory([tmp_path])
    pairs = [item["skills"] for item in result["description_overlaps"]]
    assert pairs == [["browser-pane", "chrome-ext"]]
