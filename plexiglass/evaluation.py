"""Deterministic, case-aware application security evaluation.

No model judges or heuristic claim of general security: verdicts apply only to
the explicit assertions and controlled fixtures supplied by the caller.
"""
from dataclasses import asdict, dataclass
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import html
import json
import math
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler

from . import __version__


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


@dataclass(frozen=True)
class TestCase:
    id: str
    suite: str
    objective: str
    messages: list
    assertion: dict

    def __post_init__(self):
        for field in ("id", "suite", "objective"):
            nonempty(getattr(self, field), field)
        if self.suite not in {"prompt_injection", "data_leakage", "benign"}:
            raise ValueError("unsupported suite")
        if not isinstance(self.messages, list) or not self.messages:
            raise ValueError("messages must be a nonempty list")
        for message in self.messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                raise ValueError("messages require role and content only")
            if message["role"] not in {"system", "user", "assistant"}:
                raise ValueError("unsupported message role")
            nonempty(message["content"], "message content")
        if not isinstance(self.assertion, dict) or set(self.assertion) != {"type", "value"}:
            raise ValueError("assertion requires type and value")
        if self.assertion["type"] not in {"not_contains", "equals"}:
            raise ValueError("unsupported assertion type")
        nonempty(self.assertion["value"], "assertion value")
        if self.suite == "data_leakage" and self.assertion["type"] != "not_contains":
            raise ValueError("data leakage requires a not_contains assertion")


def load_cases(path):
    cases = []
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            cases.append(TestCase(**json.loads(line)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid case at line {number}: {exc}") from exc
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("cases must be nonempty with unique IDs")
    return cases


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTPTarget:
    """POST messages to a JSON application; extract a configured response path."""

    def __init__(self, url, response_path="response", body=None, api_key_env=None, timeout=30):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("put credentials in an environment variable, not the URL")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        nonempty(response_path, "response_path")
        if body is not None and not isinstance(body, dict):
            raise ValueError("body must be an object")
        if body and "messages" in body:
            raise ValueError("body must not override messages")
        self.url, self.response_path = url, response_path
        self.body, self.timeout = body or {}, timeout
        self.token = None
        if api_key_env:
            self.token = os.environ.get(api_key_env)
            if not self.token:
                raise ValueError(f"missing credential environment variable: {api_key_env}")

    def manifest(self):
        return {"type": "http", "url": self.url, "response_path": self.response_path,
                "body_sha256": digest(self.body), "timeout_seconds": self.timeout}

    def __call__(self, messages):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(self.url, data=json.dumps({**self.body, "messages": messages}).encode(),
                          headers=headers, method="POST")
        # Never forward a credential to a redirected endpoint.
        try:
            with build_opener(NoRedirect).open(request, timeout=self.timeout) as response:
                raw = response.read(10_000_001)
        except HTTPError as exc:
            exc.close()
            raise
        if len(raw) > 10_000_000:
            raise ValueError("response exceeds 10 MB")
        value = json.loads(raw)
        for part in self.response_path.split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        if not isinstance(value, str):
            raise ValueError("response path must resolve to text")
        return value


def evaluate_case(case, response):
    """Return a security assertion verdict with exact response evidence."""
    if not isinstance(response, str):
        raise ValueError("target response must be text")
    expected = case.assertion["value"]
    if case.assertion["type"] == "not_contains":
        start = response.casefold().find(expected.casefold())
        passed = start < 0
        evidence = None if passed else {"matched_value": expected}
    else:
        passed = response.strip() == expected
        evidence = None if passed else {"expected": expected, "actual": response}
    return {"status": "pass" if passed else "fail", "evidence": evidence,
            "reason": f"{case.assertion['type']} assertion {'satisfied' if passed else 'violated'}"}


def run(cases, target, output, *, max_cases=100):
    """Evaluate cases and persist complete evidence before returning the report.

    Callable targets implement ``target(messages) -> str``. HTTP targets add a
    reproducibility manifest. Output directories must be new to avoid overwrites.
    """
    if not cases or len(cases) > max_cases or max_cases < 1:
        raise ValueError("case count must be between 1 and max_cases")
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("duplicate case IDs")
    serialized = [asdict(case) for case in cases]
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {"schema_version": 1, "evaluator_version": "deterministic-v1",
                "plexiglass_version": __version__, "started_at": datetime.now(timezone.utc).isoformat(),
                "cases_sha256": digest(serialized), "cases": serialized,
                "target": target.manifest() if hasattr(target, "manifest") else {"type": "callable"},
                "max_cases": max_cases}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2))
    results = []
    with (destination / "results.jsonl").open("w") as stream:
        for case in cases:
            result = {"id": case.id, "suite": case.suite, "case": asdict(case)}
            started = time.monotonic()
            try:
                response = target(deepcopy(case.messages))
                result["response"] = response if isinstance(response, str) else None
            except Exception as exc:
                # Exception messages can contain credentials or server content.
                result.update(status="target_error", error_type=type(exc).__name__)
            else:
                try:
                    result.update(evaluate_case(case, response))
                except Exception as exc:
                    result.update(status="evaluation_error", error_type=type(exc).__name__)
            result["latency_seconds"] = time.monotonic() - started
            results.append(result)
            stream.write(json.dumps(result, ensure_ascii=False) + "\n")
            stream.flush()
    summary = {status: sum(r["status"] == status for r in results)
               for status in ("pass", "fail", "target_error", "evaluation_error")}
    summary["total"] = len(results)
    report = {"manifest": manifest, "summary": summary, "results": results}
    (destination / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    rows = "".join(
        "<tr>" + "".join(f"<td><pre>{html.escape(str(value))}</pre></td>" for value in
                       (r["id"], r["status"], r.get("reason", r.get("error_type")),
                        json.dumps(r["case"]["messages"], ensure_ascii=False), r.get("response", ""))) + "</tr>"
        for r in results)
    (destination / "report.html").write_text(
        '<!doctype html><meta charset="utf-8"><title>Plexiglass evaluation</title>'
        '<style>body{font:16px sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}'
        'td,th{border:1px solid #bbb;padding:.5rem;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
        '<h1>Plexiglass evaluation</h1><p>Verdicts apply only to the supplied fixture assertions.</p>'
        f'<pre>{html.escape(json.dumps(summary, indent=2))}</pre>'
        '<table><tr><th>Case</th><th>Status</th><th>Reason</th><th>Messages</th><th>Response</th></tr>'
        + rows + '</table>')
    return report


def validate_report(report):
    manifest = report["manifest"]
    if manifest["schema_version"] != 1 or manifest["evaluator_version"] != "deterministic-v1":
        raise ValueError("unsupported report version")
    cases = [TestCase(**case) for case in manifest["cases"]]
    expected = {case.id for case in cases}
    if not cases or len(expected) != len(cases) or digest(manifest["cases"]) != manifest["cases_sha256"]:
        raise ValueError("invalid case manifest")
    rows = report["results"]
    if len(rows) != len(expected) or {row["id"] for row in rows} != expected:
        raise ValueError("incomplete report")
    case_map = {case.id: asdict(case) for case in cases}
    for row in rows:
        if row["case"] != case_map[row["id"]] or row["status"] not in {"pass", "fail"}:
            raise ValueError("invalid or inconclusive evaluation")
        if evaluate_case(TestCase(**row["case"]), row["response"])["status"] != row["status"]:
            raise ValueError("verdict does not match preserved evidence")


def compare(current, baseline):
    """Compare the same versioned cases, rejecting incomplete/error baselines."""
    validate_report(current)
    validate_report(baseline)
    for key in ("schema_version", "evaluator_version", "cases_sha256"):
        if current["manifest"][key] != baseline["manifest"][key]:
            raise ValueError(f"incompatible baseline: {key}")
    expected = {case["id"] for case in current["manifest"]["cases"]}
    indexed = []
    for report in (current, baseline):
        rows = report["results"]
        indexed.append({row["id"]: row["status"] for row in rows})
    new, old = indexed
    return {"regressions": sorted(i for i in expected if old[i] == "pass" and new[i] == "fail"),
            "improvements": sorted(i for i in expected if old[i] == "fail" and new[i] == "pass")}
