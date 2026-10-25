import json
import socket

import pytest
import pytest_asyncio
from agents import FunctionTool
from agents.tool_context import ToolContext

from src.tools.threat_intel import lookup_ip_reputation, threat_intel


@pytest_asyncio.fixture(autouse=True)
async def forbid_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def fail_network(*args, **kwargs):
        pytest.fail("Lookup attempted network access.")

    monkeypatch.setattr(socket, "getaddrinfo", fail_network)
    monkeypatch.setattr(socket.socket, "connect", fail_network)
    yield


@pytest.mark.parametrize(
    "address,reputation,confidence",
    [
        ("203.0.113.10", "suspicious", 0.9),
        ("198.51.100.20", "benign", 0.8),
        ("203.0.113.99", "unknown", 0.0),
        ("2001:db8::1", "unknown", 0.0),
    ],
)
def test_reputation_results(address, reputation, confidence):
    result = lookup_ip_reputation(address)
    assert set(result) == {"reputation", "confidence", "source", "note"}
    assert result["reputation"] == reputation
    assert result["confidence"] == confidence
    assert result["source"] == "synthetic-local-db"
    assert isinstance(result["note"], str) and result["note"]
    if reputation == "unknown":
        assert "unknown does not mean safe" in result["note"]


@pytest.mark.parametrize(
    "address",
    ["", "not-an-ip", "999.1.1.1", "203.0.113.0/24", "https://203.0.113.10", None, 123],
)
def test_invalid_addresses(address):
    result = lookup_ip_reputation(address)
    assert result["reputation"] == "invalid"
    assert result["confidence"] == 0.0
    assert result["source"] == "synthetic-local-db"
    assert "valid IPv4 or IPv6" in result["note"]


def test_results_are_deterministic_and_cannot_mutate_database():
    expected = lookup_ip_reputation("203.0.113.10")
    modified = lookup_ip_reputation("203.0.113.10")
    modified["reputation"] = "benign"
    assert lookup_ip_reputation("203.0.113.10") == expected


def test_function_tool_schema():
    assert isinstance(threat_intel, FunctionTool)
    assert threat_intel.name == "threat_intel"
    schema = threat_intel.params_json_schema
    assert schema["properties"]["ip_address"]["type"] == "string"
    assert schema["required"] == ["ip_address"]
    assert schema["additionalProperties"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["203.0.113.10", "2001:db8::1", "not-an-ip"])
async def test_sdk_invocation(address):
    arguments = json.dumps({"ip_address": address})
    context = ToolContext(
        context=None,
        tool_name=threat_intel.name,
        tool_call_id="synthetic-call",
        tool_arguments=arguments,
    )
    result = await threat_intel.on_invoke_tool(context, arguments)
    if isinstance(result, str):
        result = json.loads(result)
    assert result == lookup_ip_reputation(address)
