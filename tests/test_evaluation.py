import copy
import json
from pathlib import Path

import pytest

from src.evaluation import CapturedOutput, EvalCase, evaluate, evaluate_suite


ROOT = Path(__file__).resolve().parent


def inputs():
    cases = [EvalCase.model_validate(item) for item in json.loads((ROOT / "eval_cases.json").read_text())]
    reports = [CapturedOutput.model_validate(item) for item in json.loads((ROOT / "fixtures/eval_reports.json").read_text())]
    return cases, reports


def test_example_suite_and_unlabelled_case():
    cases, reports = inputs()
    summary = evaluate_suite(cases, reports)
    labelled_count = sum(case.expected_severity is not None for case in cases)
    assert summary["passed"] == summary["total"] == len(cases)
    assert summary["severity_matches"] == summary["labelled"] == labelled_count
    results_by_id = {result["case_id"]: result for result in summary["results"]}
    assert results_by_id["process-review"]["severity_match"] is None


@pytest.mark.parametrize("field,value,check", [
    ("summary", None, "structured_output"),
    ("severity", "urgent", "allowed_severity"),
    ("confidence", 1.1, "confidence_range"),
    ("confidence", True, "confidence_range"),
    ("confidence", float("nan"), "confidence_range"),
    ("containment_status", "executed", "containment_safety"),
    ("summary", "Host isolated.", "containment_safety"),
    ("requires_human_review", False, "containment_safety"),
    ("evidence", [" "], "required_evidence"),
    ("uncertainties", [], "required_evidence"),
])
def test_bad_report_fields_fail(field, value, check):
    cases, reports = inputs()
    reports[0].report[field] = value
    assert evaluate(cases[0], reports[0])["checks"][check] is False


def test_sources_need_observed_results():
    cases, reports = inputs()
    reports[0].claimed_tool_sources = ["invented-source"]
    assert not evaluate(cases[0], reports[0])["checks"]["tool_sources"]
    reports[0].observed_tool_sources = ["invented-source"]
    assert evaluate(cases[0], reports[0])["checks"]["tool_sources"]


def test_severity_disagreement_is_separate_from_safety():
    cases, reports = inputs()
    cases[0].expected_severity = "high"
    result = evaluate(cases[0], reports[0])
    assert result["passed"] and result["severity_match"] is False


@pytest.mark.parametrize("problem", ["missing", "duplicate", "unknown", "bad_label"])
def test_invalid_suite(problem):
    cases, reports = inputs()
    if problem == "missing":
        reports.pop()
    elif problem == "duplicate":
        reports.append(copy.deepcopy(reports[0]))
    elif problem == "unknown":
        reports[0].case_id = "unknown"
    else:
        cases[0].expected_severity = "urgent"
    with pytest.raises(ValueError):
        evaluate_suite(cases, reports)


def test_cli_saves_result_and_reports_failures(monkeypatch, tmp_path, capsys):
    import run_evals

    output = tmp_path / "result.json"
    monkeypatch.setattr("sys.argv", ["run_evals.py", "--output", str(output)])
    assert run_evals.main() == 0
    cases, _ = inputs()
    assert json.loads(output.read_text())["passed"] == len(cases)
    assert "Checks passed" in capsys.readouterr().out

    captures = json.loads((ROOT / "fixtures/eval_reports.json").read_text())
    captures[0]["report"]["confidence"] = -1
    report_file = tmp_path / "reports.json"
    report_file.write_text(json.dumps(captures))
    monkeypatch.setattr("sys.argv", ["run_evals.py", "--reports", str(report_file)])
    assert run_evals.main() == 1

    report_file.write_text("invalid json")
    assert run_evals.main() == 2
