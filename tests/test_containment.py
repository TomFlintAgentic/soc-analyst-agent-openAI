import json
import socket
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from agents import Agent, Model, Runner, RunConfig
from agents.items import ModelResponse
from agents.usage import Usage
from agents.exceptions import UserError
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from src.agents.containment_agent import create_containment_agent, review_containment
from src.tools.containment import request_host_isolation


class IsolationModel(Model):
    """Ask for isolation once, then end after receiving the tool result."""

    def __init__(self, arguments=None):
        self.calls = 0
        self.arguments = arguments or {"hostname": "training-host", "reason": "Synthetic alert"}

    async def get_response(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            output = ResponseFunctionToolCall(
                id="synthetic-tool", call_id="synthetic-isolation", type="function_call",
                name="request_host_isolation", arguments=json.dumps(self.arguments),
            )
        else:
            output = ResponseOutputMessage(
                id="synthetic-message", type="message", role="assistant", status="completed",
                content=[ResponseOutputText(type="output_text", text="Review complete.", annotations=[])],
            )
        return ModelResponse(output=[output], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


@pytest_asyncio.fixture(autouse=True)
async def block_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Containment tests must not access the network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "1")


async def paused_run(monkeypatch, arguments=None):
    original = request_host_isolation.on_invoke_tool
    async def invoke_original(context, arguments):
        return await original(context, arguments)
    invoke = AsyncMock(side_effect=invoke_original)
    monkeypatch.setattr(request_host_isolation, "on_invoke_tool", invoke)
    agent = Agent(name="Offline review", model=IsolationModel(arguments), tools=[request_host_isolation])
    result = await Runner.run(agent, "Synthetic isolation request", run_config=RunConfig(tracing_disabled=True))
    assert len(result.interruptions) == 1
    invoke.assert_not_awaited()
    return agent, result, invoke


@pytest.mark.asyncio
async def test_no_decision_keeps_tool_paused(monkeypatch):
    agent, result, invoke = await paused_run(monkeypatch)
    resumed = await Runner.run(agent, result.to_state(), run_config=RunConfig(tracing_disabled=True))
    assert resumed.interruptions
    invoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejection_never_invokes_tool(monkeypatch):
    agent, result, invoke = await paused_run(monkeypatch)
    state = result.to_state()
    state.reject(result.interruptions[0])
    result = await Runner.run(agent, state, run_config=RunConfig(tracing_disabled=True))
    assert not result.interruptions
    invoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_approval_runs_simulation_once(monkeypatch, capsys):
    _, result, invoke = await paused_run(monkeypatch)

    def approve(prompt):
        displayed = capsys.readouterr().out
        assert "training-host" in displayed
        assert "Synthetic alert" in displayed
        assert "SIMULATED effect" in displayed
        return "APPROVE"

    monkeypatch.setattr("builtins.input", approve)
    result = await review_containment(result)
    invoke.assert_awaited_once()
    outputs = [item.output for item in result.new_items if item.type == "tool_call_output_item"]
    assert any("SIMULATED" in output and "No EDR platform was contacted" in output for output in outputs)


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["", "yes", "approve", "DENY", None])
async def test_console_fails_closed(monkeypatch, decision):
    _, result, invoke = await paused_run(monkeypatch)

    def respond(prompt):
        if decision is None:
            raise EOFError
        return decision

    monkeypatch.setattr("builtins.input", respond)
    await review_containment(result)
    invoke.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    {"hostname": " ", "reason": "Synthetic alert"},
    {"hostname": "training-host", "reason": " "},
])
async def test_invalid_arguments_fail_after_approval(monkeypatch, arguments):
    agent, result, _ = await paused_run(monkeypatch, arguments)
    state = result.to_state()
    state.approve(result.interruptions[0])
    with pytest.raises(UserError, match="nonempty"):
        await Runner.run(agent, state, run_config=RunConfig(tracing_disabled=True))


def test_workflow_tool_requires_sdk_approval():
    agent = create_containment_agent(model="test-model")
    assert agent.tools == [request_host_isolation]
    assert request_host_isolation.needs_approval is True
    assert agent.handoffs == []
