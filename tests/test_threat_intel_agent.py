import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agents import Runner
from agents.tool_context import ToolContext
from pydantic import ValidationError

from src.agents.threat_intel_agent import (
    ThreatIntelEvidence,
    create_threat_intel_agent,
    create_threat_intel_tool,
)
from src.tools.threat_intel import lookup_ip_reputation, threat_intel


def test_specialist_has_only_approved_tools_and_no_handoff():
    agent = create_threat_intel_agent(model="test-model")
    assert agent.tools == [threat_intel]
    assert agent.handoffs == []
    assert agent.mcp_servers == []
    assert agent.output_type is ThreatIntelEvidence
    assert agent.model == "test-model"


def test_evidence_rejects_incident_verdict():
    with pytest.raises(ValidationError):
        ThreatIntelEvidence(findings=[], limitations=[], severity="critical")


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["203.0.113.10", "203.0.113.99", "not-an-ip"])
async def test_agent_as_tool_returns_evidence(monkeypatch, address):
    reputation = lookup_ip_reputation(address)
    evidence = ThreatIntelEvidence(
        findings=[dict(ioc=address, status=reputation.pop("reputation"), **reputation)],
        limitations=["Synthetic local evidence only."],
    )
    run = AsyncMock(return_value=SimpleNamespace(final_output=evidence))
    monkeypatch.setattr(Runner, "run", run)
    tool = create_threat_intel_tool(model="test-model")
    incident = json.dumps({"id": "synthetic-1", "src_ip": address})
    arguments = json.dumps({"input": incident})
    context = ToolContext(context=None, tool_name=tool.name,
                          tool_call_id="synthetic-call", tool_arguments=arguments)
    output = await tool.on_invoke_tool(context, arguments)
    assert json.loads(output) == evidence.model_dump()
    assert run.call_args.kwargs["input"] == incident
    assert run.call_args.kwargs["starting_agent"].tools == [threat_intel]


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_output", [False, True])
async def test_specialist_failure_propagates(monkeypatch, invalid_output):
    run = AsyncMock(return_value=SimpleNamespace(final_output={})) if invalid_output else AsyncMock(
        side_effect=RuntimeError("Specialist failed")
    )
    monkeypatch.setattr(Runner, "run", run)
    tool = create_threat_intel_tool(model="test-model")
    arguments = json.dumps({"input": '{"id":"synthetic-1"}'})
    context = ToolContext(context=None, tool_name=tool.name,
                          tool_call_id="synthetic-call", tool_arguments=arguments)
    with pytest.raises(ValidationError if invalid_output else RuntimeError):
        await tool.on_invoke_tool(context, arguments)
