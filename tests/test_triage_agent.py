import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from agents.tool_context import ToolContext
from src.agents.triage_agent import create_triage_agent, triage_alerts
from src.models.response import ResponsePlan
from src.models.alert import Alert
from src.models.report import SOCReport


def make_alert(alert_id="synthetic-1"):
    return Alert(
        id=alert_id,
        source="synthetic",
        timestamp="2026-01-01T12:00:00Z",
        alert_type="failed_login",
        description="Three unsuccessful sign-in attempts on a training account.",
    )


def make_report(severity="medium"):
    return SOCReport(
        incident_id="model-generated-id",
        severity=severity,
        confidence=0.5,
        summary="Suspicious sign-ins. No external lookup was performed.",
        evidence=["synthetic-1: three unsuccessful sign-in attempts"],
        uncertainties=["Successful sign-ins and malicious intent are unconfirmed."],
        iocs=[],
        attack_techniques=[],
        recommended_actions=["Ask an analyst to review the supplied alert."],
        requires_human_review=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 2])
async def test_reports_and_human_review(monkeypatch, count):
    run = AsyncMock(side_effect=[SimpleNamespace(final_output=make_report()) for _ in range(count)])
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", run)
    alerts = [make_alert(f"synthetic-{index}") for index in range(count)]
    reports = await triage_alerts(alerts[0] if count == 1 else alerts, model="test-model")
    assert [report.incident_id for report in reports] == [f"incident-{alert.id}" for alert in alerts]
    assert all(report.requires_human_review for report in reports)
    assert run.await_count == count
    agent = run.call_args.args[0]
    assert [tool.name for tool in agent.tools] == [
        "inspect_incident_iocs", "investigate_supplied_alerts", "plan_read_only_response",
    ]
    assert agent.handoffs == []
    assert agent.output_type is SOCReport
    assert run.call_args.kwargs["input"] == alerts[-1].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("alerts", [None, 42, "invalid", {}, (), [], ["invalid"]])
async def test_invalid_input_does_not_call_sdk(monkeypatch, alerts):
    run = AsyncMock()
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", run)
    with pytest.raises(ValueError, match="validated Alert"):
        await triage_alerts(alerts, model="test-model")
    run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("output,error", [(make_report("urgent"), ValueError), ({}, ValidationError)])
async def test_invalid_report_is_rejected(monkeypatch, output, error):
    monkeypatch.setattr(
        "src.agents.triage_agent.Runner.run",
        AsyncMock(return_value=SimpleNamespace(final_output=output)),
    )
    with pytest.raises(error):
        await triage_alerts(make_alert(), model="test-model")


@pytest.mark.asyncio
async def test_api_failure_is_not_replaced_with_a_report(monkeypatch):
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", AsyncMock(side_effect=RuntimeError("API failed")))
    with pytest.raises(RuntimeError, match="API failed"):
        await triage_alerts(make_alert(), model="test-model")


def test_malformed_alert_is_rejected():
    with pytest.raises(ValidationError):
        Alert.model_validate({"id": "synthetic-invalid"})


async def invoke_tool(tool, arguments):
    serialized = json.dumps(arguments)
    context = ToolContext(context=None, tool_name=tool.name,
                          tool_call_id="synthetic-call", tool_arguments=serialized)
    return await tool.on_invoke_tool(context, serialized)


@pytest.mark.asyncio
async def test_investigation_uses_original_batch_without_model_call(monkeypatch):
    run = AsyncMock()
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", run)
    alerts = [make_alert("synthetic-1"), make_alert("synthetic-2")]
    for alert in alerts:
        alert.hostname = "training-host"
    tool = create_triage_agent(alerts, model="test-model").tools[1]
    evidence = json.loads(await invoke_tool(tool, {}))
    assert evidence["correlations"][0]["alert_ids"] == ["synthetic-1", "synthetic-2"]
    assert evidence["correlations"][0]["shared_fields"] == {"hostname": "training-host"}
    assert "severity" not in evidence
    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_response_tool_returns_advice_and_keeps_report_provisional(monkeypatch):
    plan = ResponsePlan(incident_id="draft", summary="Review evidence",
                        investigate=[{"description": "Review sign-in logs", "rationale": "Confirm source claims"}],
                        containment=[], limitations=["Synthetic evidence only"])
    recommend = AsyncMock(return_value=plan)
    monkeypatch.setattr("src.agents.triage_agent.recommend_response", recommend)
    tool = create_triage_agent([make_alert()], model="test-model").tools[2]
    draft = make_report()
    output = json.loads(await invoke_tool(tool, {"report_json": draft.model_dump_json()}))
    assert output == plan.model_dump()
    assert recommend.call_args.args[0] == draft
    assert recommend.call_args.kwargs == {"model": "test-model", "read_only": True}
    assert "severity" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", [True, False])
async def test_response_tool_rejects_bad_draft_and_propagates_failure(monkeypatch, malformed):
    recommend = AsyncMock(side_effect=RuntimeError("Specialist failed"))
    monkeypatch.setattr("src.agents.triage_agent.recommend_response", recommend)
    tool = create_triage_agent([make_alert()], model="test-model").tools[2]
    with pytest.raises(ValidationError if malformed else RuntimeError):
        await invoke_tool(tool, {"report_json": "{}" if malformed else make_report().model_dump_json()})
    if malformed:
        recommend.assert_not_awaited()


@pytest.mark.asyncio
async def test_mutated_report_is_revalidated(monkeypatch):
    report = make_report()
    report.confidence = 2
    monkeypatch.setattr("src.agents.triage_agent.Runner.run",
                        AsyncMock(return_value=SimpleNamespace(final_output=report)))
    with pytest.raises(ValidationError):
        await triage_alerts(make_alert(), model="test-model")


@pytest.mark.parametrize("field", ["id", "source", "alert_type", "description"])
@pytest.mark.parametrize("value", ["", " \t\n", None, 42, [], {}])
def test_required_alert_text_is_validated(field, value):
    data = make_alert().model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["blank", "timestamp", "raw_data", "duplicate", "constructed"])
async def test_entire_batch_is_checked_before_sdk(monkeypatch, invalid):
    first, second = make_alert(), make_alert("synthetic-2")
    if invalid == "blank":
        second.description = " "
    elif invalid == "timestamp":
        second.timestamp = "not-a-date"
    elif invalid == "raw_data":
        second.raw_data = []
    elif invalid == "duplicate":
        second.id = first.id
    else:
        second = Alert.model_construct(id="synthetic-invalid")
    run = AsyncMock()
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", run)
    with pytest.raises(ValueError):
        await triage_alerts([first, second], model="test-model")
    run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", [
    "summary", "evidence", "uncertainties", "recommended_actions", "attack_techniques", "iocs",
])
@pytest.mark.parametrize("claim", [
    "The training host was isolated.", "We disabled the account.",
    "The account has been disabled.", "Traffic was blocked.",
    "Quarantine completed.", "Containment succeeded.", "Access was revoked.",
])
async def test_containment_prose_is_rejected_in_every_field(monkeypatch, field, claim):
    output = make_report().model_dump()
    output[field] = claim if field == "summary" else [claim]
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", AsyncMock(
        return_value=SimpleNamespace(final_output=output),
    ))
    with pytest.raises(ValueError, match="must not narrate containment"):
        await triage_alerts(make_alert(), model="test-model")


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("evidence", []), ("evidence", [" "]),
    ("uncertainties", []), ("uncertainties", [" "]),
    ("evidence", ["The host might be compromised."]),
])
async def test_evidence_uncertainty_contract(monkeypatch, field, value):
    output = make_report().model_dump()
    output[field] = value
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", AsyncMock(
        return_value=SimpleNamespace(final_output=output),
    ))
    with pytest.raises(ValueError):
        await triage_alerts(make_alert(), model="test-model")


@pytest.mark.asyncio
async def test_hypothesis_stays_separate_from_evidence(monkeypatch):
    output = make_report().model_dump()
    output["uncertainties"] = ["The sign-ins may be benign; successful access is unknown."]
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", AsyncMock(
        return_value=SimpleNamespace(final_output=output),
    ))
    report, = await triage_alerts(make_alert(), model="test-model")
    assert report.evidence == output["evidence"]
    assert report.uncertainties == output["uncertainties"]
    assert report.containment_status == "not_performed"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("containment_status", "performed"), ("executed", True)])
async def test_execution_metadata_is_rejected(monkeypatch, field, value):
    output = make_report().model_dump()
    output[field] = value
    monkeypatch.setattr("src.agents.triage_agent.Runner.run", AsyncMock(
        return_value=SimpleNamespace(final_output=output),
    ))
    with pytest.raises(ValidationError):
        await triage_alerts(make_alert(), model="test-model")
