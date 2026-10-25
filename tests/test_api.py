import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from agents.exceptions import MaxTurnsExceeded, ModelBehaviorError
from openai import APIError, APITimeoutError, RateLimitError

from src import api
from src.models.alert import Alert
from src.models.report import SOCReport


def test_main_exposes_api_app(client):
    from src.main import app

    assert app is api.app
    assert client.get("/health").status_code == 200
    assert "/analyse" in client.get("/openapi.json").json()["paths"]


@pytest.fixture
def alert_data():
    return {
        "id": "synthetic-1", "source": "training",
        "timestamp": "2026-01-01T12:00:00Z", "alert_type": "failed_login",
        "description": "Three unsuccessful sign-ins on a training account.",
    }


@pytest.fixture
def report():
    return SOCReport(
        incident_id="incident-synthetic-1", severity="medium", confidence=0.5,
        summary="Synthetic assessment. No external lookup was performed.",
        evidence=["synthetic-1 reports three unsuccessful sign-ins."],
        uncertainties=["No additional training telemetry supplied."],
        iocs=[], attack_techniques=[], recommended_actions=["Review training logs."],
    )


@pytest.fixture
def client(monkeypatch, report):
    monkeypatch.setattr(api, "load_dotenv", lambda path: None)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    monkeypatch.setattr(api, "triage_alerts", AsyncMock(return_value=[report]))
    with TestClient(api.app) as test_client:
        yield test_client


def test_health_without_credentials(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.delenv("OPENAI_MODEL")
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    api.triage_alerts.assert_not_awaited()


@pytest.mark.parametrize("count", [1, 2])
def test_analyse_returns_reports(client, alert_data, report, count):
    alerts = [dict(alert_data, id=f"synthetic-{index + 1}") for index in range(count)]
    reports = [report.model_copy(update={"incident_id": f"incident-{alert['id']}"})
               for alert in alerts]
    api.triage_alerts.return_value = reports
    response = client.post("/analyse", json={"alerts": alerts})
    assert response.status_code == 200
    assert response.json() == {"reports": [item.model_dump(mode="json") for item in reports]}
    api.triage_alerts.assert_awaited_once_with(
        [Alert.model_validate(item) for item in alerts], model="test-model",
    )
    assert all(item["requires_human_review"] for item in response.json()["reports"])
    assert all(item["containment_status"] == "not_performed"
               for item in response.json()["reports"])


@pytest.mark.parametrize("case", ["missing", "empty", "blank", "timestamp", "duplicate", "extra"])
def test_invalid_request_stops_before_workflow(client, alert_data, case):
    body = {"alerts": [alert_data]}
    if case == "missing":
        body = {}
    elif case == "empty":
        body["alerts"] = []
    elif case == "blank":
        alert_data["description"] = " "
    elif case == "timestamp":
        alert_data["timestamp"] = "invalid"
    elif case == "duplicate":
        body["alerts"].append(dict(alert_data))
    else:
        body["approve_containment"] = True
    response = client.post("/analyse", json=body)
    assert response.status_code == 422
    assert response.json()["detail"]
    api.triage_alerts.assert_not_awaited()


def test_malformed_json(client):
    response = client.post("/analyse", content="{", headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    api.triage_alerts.assert_not_awaited()


@pytest.mark.parametrize("variable", ["OPENAI_API_KEY", "OPENAI_MODEL"])
def test_missing_configuration(client, alert_data, monkeypatch, variable):
    monkeypatch.setenv(variable, " ")
    response = client.post("/analyse", json={"alerts": [alert_data]})
    assert response.status_code == 503
    assert variable in response.json()["detail"]
    api.triage_alerts.assert_not_awaited()


@pytest.mark.parametrize("failure,status", [
    (ValueError("private generated data"), 502),
    (RuntimeError("private credential"), 500),
    (ModelBehaviorError("private model output"), 502),
    (MaxTurnsExceeded("private run details"), 502),
    (APIError("private upstream data", httpx.Request("POST", "https://example.invalid"), body=None), 502),
    (APITimeoutError(httpx.Request("POST", "https://example.invalid")), 504),
    (RateLimitError("private rate limit data", response=httpx.Response(
        429, request=httpx.Request("POST", "https://example.invalid")), body=None), 503),
])
def test_workflow_errors_are_safe(client, alert_data, failure, status):
    api.triage_alerts.side_effect = failure
    response = client.post("/analyse", json={"alerts": [alert_data]})
    assert response.status_code == status
    assert "private" not in response.text
    assert "synthetic-test-key" not in response.text


def test_deadline_cancels_workflow(client, alert_data, monkeypatch):
    cancelled = []

    async def slow_triage(*args, **kwargs):
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(True)

    monkeypatch.setattr(api, "triage_alerts", slow_triage)
    monkeypatch.setattr(api, "ANALYSIS_TIMEOUT_SECONDS", 0.01)
    response = client.post("/analyse", json={"alerts": [alert_data]})
    assert response.status_code == 504
    assert cancelled == [True]


def test_invalid_output_is_not_returned(client, alert_data):
    api.triage_alerts.return_value = [{"summary": "private invalid output"}]
    response = client.post("/analyse", json={"alerts": [alert_data]})
    assert response.status_code == 502
    assert "private" not in response.text


def test_unexpected_failure_logs_safe_diagnostics(client, alert_data, caplog):
    api.triage_alerts.side_effect = RuntimeError("private credential synthetic-test-key")
    response = client.post("/analyse", json={"alerts": [alert_data]})
    assert response.status_code == 500
    assert "SOC workflow failed (RuntimeError)" in caplog.text
    assert "api.py:" in caplog.text
    assert "private credential" not in caplog.text
    assert "synthetic-test-key" not in caplog.text
