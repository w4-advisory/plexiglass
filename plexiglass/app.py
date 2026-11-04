"""Non-interactive, dependency-free evaluation CLI."""
import argparse
import json
from pathlib import Path
import sys

from .evaluation import HTTPTarget, compare, load_cases, run, validate_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate explicit application security assertions")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--cases", required=True, help="Versioned JSONL test cases")
    scan.add_argument("--target", required=True, help="JSON HTTP endpoint")
    scan.add_argument("--output", required=True, help="New evidence directory")
    scan.add_argument("--response-path", default="response")
    scan.add_argument("--body", default="{}", help="Extra JSON request fields (never put secrets here)")
    scan.add_argument("--api-key-env", help="Environment variable containing bearer token")
    scan.add_argument("--timeout", type=float, default=30)
    scan.add_argument("--max-cases", type=int, default=100)
    scan.add_argument("--baseline", help="Prior report.json; fail only on regressions")
    diff = commands.add_parser("compare")
    diff.add_argument("--current", required=True)
    diff.add_argument("--baseline", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            delta = compare(json.loads(Path(args.current).read_text()),
                            json.loads(Path(args.baseline).read_text()))
            print(json.dumps(delta, indent=2))
            return 1 if delta["regressions"] else 0
        cases = load_cases(args.cases)
        target = HTTPTarget(args.target, args.response_path, json.loads(args.body),
                            args.api_key_env, args.timeout)
        baseline = json.loads(Path(args.baseline).read_text()) if args.baseline else None
        if baseline is not None:
            validate_report(baseline)
            # Validate compatibility before making any remote requests.
            from .evaluation import digest
            from dataclasses import asdict
            if baseline["manifest"]["cases_sha256"] != digest([asdict(c) for c in cases]):
                raise ValueError("incompatible baseline: cases_sha256")
        report = run(cases, target, args.output, max_cases=args.max_cases)
        print(json.dumps(report["summary"], indent=2))
        if report["summary"]["target_error"] or report["summary"]["evaluation_error"]:
            return 2
        if baseline is not None:
            delta = compare(report, baseline)
            Path(args.output, "comparison.json").write_text(json.dumps(delta, indent=2))
            print(json.dumps(delta, indent=2))
            return 1 if delta["regressions"] else 0
        return 1 if report["summary"]["fail"] else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Evaluation could not complete ({type(exc).__name__}); check configuration and report compatibility.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
