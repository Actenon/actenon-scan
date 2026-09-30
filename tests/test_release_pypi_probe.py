"""Execute the release workflow's PyPI probe under GitHub's bash flags."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("bash", "curl", "python3")),
    reason="bash, curl and python3 required for the release probe",
)


def _probe(responses: list[tuple[int, bytes]]) -> tuple[subprocess.CompletedProcess, int]:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/release-v1-tag.yml").read_text()
    )
    step = next(
        step for step in workflow["jobs"]["release-gate"]["steps"]
        if step.get("name") == "Wait for PyPI propagation"
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = responses[min(len(requests), len(responses) - 1)]
            requests.append(self.path)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                # Slow chunks also exercise the early-closing-pipe regression.
                for offset in range(0, len(body), 1024):
                    self.wfile.write(body[offset:offset + 1024])
                    self.wfile.flush()
                    time.sleep(0.002)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        script = step["run"].replace("${{ steps.tag.outputs.tag }}", "v1.5.0")
        script = script.replace(
            "https://pypi.org", f"http://127.0.0.1:{server.server_port}"
        ).replace("sleep 15", "sleep 0.01")
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "NO_PROXY": "127.0.0.1"},
        )
        assert all(path == "/pypi/actenon-scan/1.5.0/json" for path in requests)
        return result, len(requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _metadata(version: str) -> bytes:
    return json.dumps({"info": {"version": version}, "padding": "x" * 32768}).encode()


def test_complete_matching_metadata_passes():
    result, attempts = _probe([(200, _metadata("1.5.0"))])
    assert result.returncode == 0, result.stderr
    assert attempts == 1
    assert "OK: version 1.5.0 is available" in result.stdout


@pytest.mark.parametrize("status,body", [
    (404, _metadata("1.5.0")),
    (503, b"temporarily unavailable"),
    (200, _metadata("1.4.0")),
    (200, b"not JSON"),
    (200, b'{"info": {}}'),
    (200, b'{"info": []}'),
], ids=["not-found", "unavailable", "wrong-version", "malformed", "missing-version", "invalid-info"])
def test_unavailable_or_invalid_metadata_fails_after_bounded_retries(status, body):
    result, attempts = _probe([(status, body)])
    assert result.returncode != 0, result.stdout
    assert attempts == 5
    assert "FAIL: version 1.5.0" in result.stderr


def test_propagation_can_recover_on_a_later_attempt():
    result, attempts = _probe([(404, b"not found"), (200, _metadata("1.5.0"))])
    assert result.returncode == 0, result.stderr
    assert attempts == 2
    assert "attempt 2" in result.stdout
