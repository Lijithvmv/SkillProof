import io
import zipfile

from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.ingestion import PackageError, read_skill_zip


client = TestClient(app)


def make_zip(entries: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return output.getvalue()


def test_zip_ingestion_flattens_single_wrapper_directory():
    files = read_skill_zip(make_zip({"package/demo-skill/SKILL.md": "---\nname: demo-skill\ndescription: demo\n---\n"}))
    assert "demo-skill/SKILL.md" in files


def test_zip_path_traversal_is_rejected():
    try:
        read_skill_zip(make_zip({"../escape.txt": "bad"}))
    except PackageError as exc:
        assert "Unsafe ZIP path" in str(exc)
    else:
        raise AssertionError("Expected unsafe path rejection")


def test_health_and_json_analysis_endpoints():
    assert client.get("/health").json()["status"] == "ok"
    response = client.post("/api/v1/skills/analyze", json={"files": {"demo-skill/SKILL.md": "---\nname: demo-skill\ndescription: demo\n---\n"}})
    assert response.status_code == 200
    assert response.json()["metadata"]["name"] == "demo-skill"


def test_zip_intelligence_endpoint():
    archive = make_zip({"demo-skill/SKILL.md": "---\nname: demo-skill\ndescription: demo\n---\n"})
    response = client.post("/api/v1/skills/intelligence", files={"file": ("skill.zip", archive, "application/zip")})
    assert response.status_code == 200
    assert response.json()["skill_path"] == "demo-skill/SKILL.md"

