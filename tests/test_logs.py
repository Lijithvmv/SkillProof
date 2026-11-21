"""Operational logs. Decision changed: an operator can trace any request (and what the background workers did) from
its request id, without skill contents or tokens in the logs."""
import json
import logging

from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.logs import JsonFormatter


def test_every_request_gets_a_request_id_and_one_json_log_line(caplog):
    caplog.set_level(logging.INFO, logger="skillproof")
    client = TestClient(app)
    response = client.get("/health", headers={"X-Request-ID": "trace-12345678"})
    assert response.headers["X-Request-ID"] == "trace-12345678"
    generated = client.get("/health", headers={"X-Request-ID": "bad id with spaces"}).headers["X-Request-ID"]
    assert len(generated) == 32 and " " not in generated
    lines = [json.loads(JsonFormatter().format(r)) for r in caplog.records if r.getMessage() == "request"]
    first = lines[0]
    assert first["request_id"] == "trace-12345678" and first["path"] == "/health" and first["status"] == 200
    assert "duration_ms" in first and "authorization" not in json.dumps(lines).lower()
