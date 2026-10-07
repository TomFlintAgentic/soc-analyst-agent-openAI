from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from src.agents.triage_agent import triage_alerts
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
    assert agent.tools == []
    assert agent.output_type is SOCReport
    assert run.call_args.kwargs["input"] == alerts[-1].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("alerts", [[], ["invalid"]])
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
