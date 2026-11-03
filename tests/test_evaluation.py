import contextlib
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from plexiglass.app import main
from plexiglass.evaluation import HTTPTarget, TestCase, compare, evaluate_case, load_cases, run

ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def server(*, vulnerable=False, malformed=False, redirect=False, nested=False, delay=0):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((request, self.headers.get("Authorization")))
            if redirect:
                self.send_response(302)
                self.send_header("Location", "/other")
                self.end_headers()
                return
            system = request["messages"][0]["content"]
            response = "4" if "arithmetic" in system else "SAFE"
            if vulnerable and "canary" in system:
                response = "PLX_SYNTHETIC_SECRET_7C91"
            if delay:
                time.sleep(delay)
            body = {"choices": [{"message": {"content": response}}]} if nested else {"response": response}
            payload = b"not json" if malformed else json.dumps(body).encode()
            self.send_response(200)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except BrokenPipeError:
                pass

        def log_message(self, *args):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", received
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases = load_cases(ROOT / "examples/security-cases.jsonl")

    def output(self, name):
        return self.root / name

    def test_defended_http_full_run(self):
        with server() as (url, received):
            report = run(self.cases, HTTPTarget(url), self.output("safe"))
        self.assertEqual(report["summary"], {"pass": 3, "fail": 0, "target_error": 0,
                                             "evaluation_error": 0, "total": 3})
        self.assertEqual(received[0][0]["messages"], self.cases[0].messages)
        self.assertEqual(json.loads((self.output("safe") / "report.json").read_text()), report)
        self.assertEqual(len((self.output("safe") / "results.jsonl").read_text().splitlines()), 3)

    def test_regression_identified(self):
        with server() as (url, _):
            baseline = run(self.cases, HTTPTarget(url), self.output("baseline"))
        with server(vulnerable=True) as (url, _):
            current = run(self.cases, HTTPTarget(url), self.output("current"))
        self.assertEqual(compare(current, baseline), {"regressions": ["leak-canary-v1"], "improvements": []})
        self.assertEqual(current["results"][1]["evidence"]["matched_value"], "PLX_SYNTHETIC_SECRET_7C91")

    def test_complete_evidence_and_errors(self):
        answer = "long response " * 1000
        report = run(self.cases, lambda _: answer, self.output("long"))
        self.assertEqual(report["results"][0]["response"], answer)

        def broken(_):
            raise RuntimeError("credential-must-not-appear")
        report = run(self.cases, broken, self.output("errors"))
        self.assertEqual(report["summary"]["target_error"], 3)
        self.assertNotIn("credential-must-not-appear", json.dumps(report))
        with self.assertRaises(ValueError):
            compare(report, report)
        report = run(self.cases, lambda _: None, self.output("bad-evaluator"))
        self.assertEqual(report["summary"]["evaluation_error"], 3)

    def test_fail_closed_http(self):
        for index, options in enumerate(({"malformed": True}, {"redirect": True})):
            with server(**options) as (url, received):
                report = run(self.cases[:1], HTTPTarget(url), self.output(f"bad-{index}"))
                self.assertEqual(len(received), 1)
                self.assertEqual(report["summary"]["target_error"], 1)

    def test_auth_is_sent_but_not_persisted(self):
        with patch.dict(os.environ, {"PLX_TEST_TOKEN": "test-bearer-secret"}):
            with server() as (url, received):
                target = HTTPTarget(url, api_key_env="PLX_TEST_TOKEN")
                report = run(self.cases, target, self.output("auth"))
        self.assertEqual(received[0][1], "Bearer test-bearer-secret")
        self.assertNotIn("test-bearer-secret", json.dumps(report))

    def test_assertions_and_case_validation(self):
        self.assertEqual(evaluate_case(self.cases[1], "plx_synthetic_secret_7c91")["status"], "fail")
        for change in ({"suite": "unknown"}, {"assertion": {"type": "unknown", "value": "x"}},
                       {"messages": []}):
            with self.assertRaises(ValueError):
                TestCase(**{**asdict(self.cases[0]), **change})
        duplicate = self.output("duplicate.jsonl")
        duplicate.write_text((json.dumps(asdict(self.cases[0])) + "\n") * 2)
        with self.assertRaises(ValueError):
            load_cases(duplicate)

    def test_limits_and_incompatible_baselines(self):
        with self.assertRaises(ValueError):
            run(self.cases, lambda _: self.fail("must not call target"), self.output("budget"), max_cases=1)
        baseline = run(self.cases, lambda _: "SAFE", self.output("base"))
        different = run(self.cases[:1], lambda _: "SAFE", self.output("other"))
        with self.assertRaises(ValueError):
            compare(different, baseline)
        baseline["results"].pop()
        with self.assertRaises(ValueError):
            compare(baseline, baseline)
        with self.assertRaises(FileExistsError):
            run(self.cases, lambda _: "SAFE", self.output("base"))

    def test_cli_exit_codes_and_baseline(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with server() as (url, _):
                code = main(["scan", "--cases", str(ROOT / "examples/security-cases.jsonl"),
                             "--target", url, "--output", str(self.output("cli-base"))])
            self.assertEqual(code, 0)
            with server(vulnerable=True) as (url, _):
                code = main(["scan", "--cases", str(ROOT / "examples/security-cases.jsonl"),
                             "--target", url, "--output", str(self.output("cli-new")),
                             "--baseline", str(self.output("cli-base/report.json"))])
            self.assertEqual(code, 1)
            self.assertEqual(main(["compare", "--current", str(self.output("cli-new/report.json")),
                                   "--baseline", str(self.output("cli-base/report.json"))]), 1)
            with server(malformed=True) as (url, _):
                code = main(["scan", "--cases", str(ROOT / "examples/security-cases.jsonl"),
                             "--target", url, "--output", str(self.output("cli-error"))])
            self.assertEqual(code, 2)

    def test_target_validation(self):
        for url in ("file:///tmp/test", "https://user:secret@example.com", "https://example.com?token=x"):
            with self.assertRaises(ValueError):
                HTTPTarget(url)
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                HTTPTarget("http://localhost", timeout=timeout)
        with self.assertRaises(ValueError):
            HTTPTarget("http://localhost", body={"messages": []})

    def test_html_escapes_untrusted_content(self):
        run(self.cases, lambda _: '<script>alert("x")</script>', self.output("html"))
        html = (self.output("html") / "report.html").read_text()
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_baseline_rejects_altered_verdict_and_evidence(self):
        report = run(self.cases, lambda _: "SAFE", self.output("tampered"))
        report["results"][0]["status"] = "fail"
        with self.assertRaises(ValueError):
            compare(report, report)

    def test_invalid_baseline_stops_before_requests(self):
        path = self.output("invalid.json")
        path.write_text("{}")
        with server() as (url, received):
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", "--cases", str(ROOT / "examples/security-cases.jsonl"),
                             "--target", url, "--output", str(self.output("never")), "--baseline", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(received, [])

    def test_target_cannot_mutate_cases(self):
        def mutating(messages):
            messages[0]["content"] = "altered"
            return "SAFE"
        original = asdict(self.cases[0])
        run(self.cases, mutating, self.output("mutation"))
        self.assertEqual(asdict(self.cases[0]), original)

    def test_nested_response_and_request_settings(self):
        with server(nested=True) as (url, received):
            target = HTTPTarget(url, "choices.0.message.content", {"model": "fixture", "temperature": 0})
            report = run(self.cases, target, self.output("nested"))
        self.assertEqual(report["summary"]["pass"], 3)
        self.assertEqual(received[0][0]["model"], "fixture")

    def test_timeout_is_inconclusive(self):
        with server(delay=.1) as (url, _):
            report = run(self.cases[:1], HTTPTarget(url, timeout=.01), self.output("timeout"))
        self.assertEqual(report["summary"]["target_error"], 1)
        self.assertEqual(report["summary"]["pass"], 0)


if __name__ == "__main__":
    unittest.main()
