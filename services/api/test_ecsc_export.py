from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ecsc_export import render_ecsc_exploit


FLAG = "ECSC{" + "A" * 32 + "}"


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return


class GeneratedExportTest(unittest.TestCase):
    def setUp(self):
        self.paths: list[str] = []

        paths = self.paths

        class VictimHandler(QuietHandler):
            def do_GET(handler):
                paths.append(handler.path)
                body = FLAG.encode()
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

        self.victim = ThreadingHTTPServer(("127.0.0.1", 0), VictimHandler)
        victim_port = self.victim.server_port

        attack_json = {
            "flag_regex": r"ECSC\{[A-Za-z0-9-_]{32}\}",
            "teams": [
                {"id": 1, "name": "NOP", "ip": "127.0.0.2"},
                {"id": 2, "name": "Test Team", "ip": "127.0.0.1"},
            ],
            "attack_info": {
                "ServiceA": {
                    "127.0.0.1": {"7": {"0": "fresh-user"}},
                }
            },
            "current_round": 7,
            "current_round_start": 1730000000,
            "current_round_until": 1730000060,
        }

        class ApiHandler(QuietHandler):
            def do_GET(handler):
                if handler.path != "/api/attack.json":
                    handler.send_error(404)
                    return
                body = json.dumps(attack_json).encode()
                handler.send_response(200)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

        self.api = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        for server in (self.victim, self.api):
            threading.Thread(target=server.serve_forever, daemon=True).start()

        self.code = render_ecsc_exploit(
            service="ServiceA",
            port=victim_port,
            protocol="http",
            candidates=["captured-user"],
            attack_info_tokens=["captured-user"],
            imports="import requests",
            exploit_body='''
url = f"http://{host}:{port}/backdoor?username=" + materialize("captured-user", flag_id)
return requests.get(url, timeout=timeout).content
''',
        )

    def tearDown(self):
        self.api.shutdown()
        self.victim.shutdown()
        self.api.server_close()
        self.victim.server_close()

    def run_export(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "rose_export.py"
            script.write_text(self.code, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(script), *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_generated_code_compiles(self):
        compile(self.code, "rose_export.py", "exec")
        self.assertLess(len(self.code.splitlines()), 140)

    def test_official_ecsc_package_resolves_and_replaces_attack_info(self):
        result = self.run_export("--api", f"http://127.0.0.1:{self.api.server_port}")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(FLAG, result.stdout.strip())
        self.assertEqual(["/backdoor?username=fresh-user"], self.paths)

    def test_single_target_mode_remains_attackfarm_friendly(self):
        result = self.run_export(
            "--host",
            "127.0.0.1",
            "--flag-id",
            "direct-user",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(FLAG, result.stdout.strip())
        self.assertEqual(["/backdoor?username=direct-user"], self.paths)


if __name__ == "__main__":
    unittest.main()
