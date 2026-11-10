import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from skillproof.cli import main
from skillproof.evaluation import BenchmarkTask
from skillproof.ollama_adapter import OllamaEvaluator, OllamaRunner



class FakeOllama:
    """A real HTTP server on 127.0.0.1 that answers /api/chat like Ollama."""

    def __init__(self):
        self.requests = []
        self.score_all_criteria = True
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                if "format" in body:
                    criteria = json.loads(body["messages"][1]["content"])["criteria"]
                    scored = criteria if owner.score_all_criteria else criteria[:-1]
                    content = json.dumps({"score": 0.5, "evidence": ["e"], "criterion_scores": [{"criterion": c, "score": 0.8, "evidence": "ok"} for c in scored]})
                else:
                    content = f"answer seed={body['options'].get('seed')}"
                reply = json.dumps({"model": body["model"], "message": {"role": "assistant", "content": content}, "prompt_eval_count": 50, "eval_count": 7}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ollama():
    server = FakeOllama()
    yield server
    server.close()


def test_runner_calls_local_chat_with_skill_only_when_enabled(ollama):
    runner = OllamaRunner(model="local-model", base_url=ollama.url, seed=5)
    baseline = runner.run(prompt="Summarize", context="Source", skill_instructions=None)
    enabled = runner.run(prompt="Summarize", context="Source", skill_instructions="Use evidence.")
    (path, first), (_, second) = ollama.requests
    assert path == "/api/chat"
    assert first["stream"] is False
    assert "Use evidence" not in json.dumps(first["messages"])
    assert "Use evidence" in second["messages"][0]["content"]
    assert baseline.provider == "ollama" and baseline.cost_usd == 0.0
    assert baseline.input_tokens == 50 and baseline.output_tokens == 7
    # Each call gets the next seed, so repeats are reproducible but not copies of each other.
    assert (first["options"]["seed"], second["options"]["seed"]) == (5, 6)
    assert enabled.output == "answer seed=6"


def test_grader_sends_json_schema_and_zero_temperature(ollama):
    task = BenchmarkTask(task_id="t", prompt="Summarize notes", criteria=["c"])
    grade = OllamaEvaluator(model="local-grader", base_url=ollama.url).evaluate(task=task, output="out")
    _, request = ollama.requests[0]
    assert request["format"]["required"] == ["score", "evidence", "criterion_scores"]
    assert request["options"]["temperature"] == 0.0
    assert grade.score == 0.8 and grade.model_overall_score == 0.5 and grade.provider == "ollama"


def test_grade_that_skips_a_criterion_is_rejected(ollama):
    ollama.score_all_criteria = False
    task = BenchmarkTask(task_id="t", prompt="Summarize notes", criteria=["a", "b"])
    with pytest.raises(ValueError, match="scored 1 of 2 criteria"):
        OllamaEvaluator(model="g", base_url=ollama.url).evaluate(task=task, output="out")


@pytest.mark.parametrize("url", ["http://192.168.1.20:11434", "http://example.com:11434", "ftp://127.0.0.1"])
def test_non_loopback_or_bad_url_is_refused(url):
    with pytest.raises(ValueError):
        OllamaRunner(model="m", base_url=url)


def test_unreachable_server_is_a_runtime_error():
    runner = OllamaRunner(model="m", base_url="http://127.0.0.1:9", timeout=2)
    with pytest.raises(RuntimeError, match="Could not reach Ollama"):
        runner.run(prompt="p", context=None, skill_instructions=None)


def test_pilot_cli_runs_end_to_end_on_ollama(ollama, tmp_path):
    root = Path(__file__).parents[1] / "examples" / "pilot"
    report, bundle, key = tmp_path / "report.json", tmp_path / "bundle.json", tmp_path / "key.json"
    code = main([
        "pilot", "--provider", "ollama", "--ollama-url", ollama.url,
        "--model", "local-model", "--grader-model", "local-grader",
        "--skill-file", str(root / "skill.md"), "--benchmark", str(root / "benchmark.jsonl"),
        "--repeats", "1", "--output", str(report), "--review-output", str(bundle), "--unblinding-key-output", str(key),
    ])
    assert code == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert sum(result["failure_counts"].values()) == 0
    assert len(json.loads(bundle.read_text(encoding="utf-8"))["review_samples"]) == 6
    # 3 tasks x 2 conditions, each one agent call and one grader call.
    assert len(ollama.requests) == 12
