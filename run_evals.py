"""Replay synthetic captured reports; no credentials, API calls, or containment."""

import argparse
import json
from pathlib import Path
import sys

from src.evaluation import CapturedOutput, EvalCase, evaluate_suite, summary_table


ROOT = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/eval_cases.json")
    parser.add_argument("--reports", type=Path, default=ROOT / "tests/fixtures/eval_reports.json")
    parser.add_argument("--output", type=Path, help="Save machine-readable evaluation results")
    args = parser.parse_args()
    try:
        cases = [EvalCase.model_validate(item) for item in json.loads(args.cases.read_text(encoding="utf-8"))]
        captures = [CapturedOutput.model_validate(item) for item in json.loads(args.reports.read_text(encoding="utf-8"))]
        summary = evaluate_suite(cases, captures)
        if args.output:
            args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError) as error:
        print(f"Evaluation input/output error ({type(error).__name__}).", file=sys.stderr)
        return 2
    print(summary_table(summary))
    return 0 if summary["passed"] == summary["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
