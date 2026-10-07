import json
from unittest.mock import AsyncMock

import pytest

import run_local
from src.models.alert import Alert
from src.models.report import SOCReport


@pytest.fixture
def local_config(monkeypatch, tmp_path):
    monkeypatch.setattr(run_local, "load_dotenv", lambda path: None)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    path = tmp_path / "alerts.json"
    monkeypatch.setattr(run_local, "ALERTS_PATH", path)
    return path


@pytest.mark.asyncio
async def test_missing_key_stops_before_triage(local_config, monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY")
    triage = AsyncMock()
    monkeypatch.setattr(run_local, "triage_alerts", triage)
    assert await run_local.main() == 1
    assert "OPENAI_API_KEY is missing" in capsys.readouterr().err
    triage.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ['{', '[]', '[{"id": "synthetic"}]'])
async def test_invalid_file_stops_before_triage(local_config, monkeypatch, capsys, content):
    local_config.write_text(content, encoding="utf-8")
    triage = AsyncMock()
    monkeypatch.setattr(run_local, "triage_alerts", triage)
    assert await run_local.main() == 1
    assert "Error loading" in capsys.readouterr().err
    triage.assert_not_awaited()


@pytest.mark.asyncio
async def test_validated_alerts_and_json_output(local_config, monkeypatch, capsys):
    data = json.loads((run_local.PROJECT_ROOT / "src/data/sample_alerts.json").read_text())
    local_config.write_text(json.dumps(data), encoding="utf-8")
    report = SOCReport(
        incident_id="incident-alert-001", severity="medium", confidence=0.5,
        summary="Synthetic assessment. No external lookup was performed.",
        evidence=[], iocs=[], attack_techniques=[], recommended_actions=[],
    )
    triage = AsyncMock(return_value=[report])
    monkeypatch.setattr(run_local, "triage_alerts", triage)
    assert await run_local.main() == 0
    assert all(isinstance(alert, Alert) for alert in triage.call_args.args[0])
    assert triage.call_args.kwargs == {"model": "test-model"}
    assert json.loads(capsys.readouterr().out) == [report.model_dump(mode="json")]
