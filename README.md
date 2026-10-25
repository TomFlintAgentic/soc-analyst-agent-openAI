# OpenAI SOC Analyst Agent

A learning and portfolio project that demonstrates an AI-assisted SOC triage workflow built with Python and the OpenAI Agents SDK.

> Status: implemented learning prototype. Uses synthetic security data only.

## Start-to-finish guide

1. Install Python with `venv` support and Git. Open PowerShell in your local clone of this repository; run all commands from the repository root.
2. Follow [Setup](#setup) to create and activate the virtual environment and install dependencies. Activate the existing environment again in later sessions.
3. Run `python -m pytest` to check the offline tests. No API key or live model calls are needed.
4. For live analysis, create the ignored `.env` with `OPENAI_API_KEY` and `OPENAI_MODEL`. Run `python .\check_models.py` to list accessible model IDs, then choose a model suitable for this workflow. Listing a model does not verify workflow compatibility.
5. Run `python .\run_local.py` to analyse `src/data/sample_alerts.json` and print structured reports. Review the evidence, uncertainties, and recommendations. Live model requests use your API account and can incur charges.
6. To use HTTP, follow [FastAPI interface](#fastapi-interface). Start Uvicorn, check `/health`, then submit synthetic alerts through `/docs` or PowerShell. Keep the server terminal open and use a second terminal for requests. Press `Ctrl+C` in the server terminal to stop it.
7. Run `python .\run_evals.py` to check the saved example reports offline. See [Evaluation runner](#evaluation-runner) for adding cases and captured outputs. This command does not generate reports or call the model.
8. Optionally explore the specialist examples and the separate [simulated isolation workflow](#human-approved-simulated-host-isolation). Each simulated action requires explicit approval at its console prompt.
9. Before committing, run `python -m pytest` and `git diff --check`. Never add secrets or real security data.

## Setup

Run these commands in PowerShell from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\src\services\requirements.txt
```

Create a local `.env` file in the repository root for live model calls:

```dotenv
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=your_available_model_id
```

The `.env` file and `.venv` directory are ignored by Git. Never commit credentials.
Existing environment variables take precedence over `.env` values. If activation
is unavailable, use `.\.venv\Scripts\python.exe` in place of `python` in subsequent
commands, including dependency installation. If `python` is not recognised but
the Windows launcher is installed, create the environment with `py -m venv .venv`.
Dependencies are currently unpinned, so installations may use different versions.

## Check available models

```powershell
python .\check_models.py
```

This script loads the local environment variables and prints the model IDs returned by the OpenAI API for your credentials. It requires internet access and a valid API key.

## Project structure

- `check_models.py`: utility for listing available models.
- `run_local.py`: loads synthetic alerts, validates them, and prints SOC reports.
- `src/main.py`: server entry point exposing the shared FastAPI app.
- `src/api.py`: HTTP routes for health checks and synthetic alert analysis.
- `src/models/api.py`: Pydantic HTTP request and response contracts.
- `src/data/sample_alerts.json`: synthetic inputs for the local runner.
- `src/agents/`: triage, threat-intelligence, investigation, response, and containment workflows.
- `src/models/`: validated alert, report, response, and HTTP contracts.
- `src/tools/`: agent tools, including the synthetic threat intelligence lookup.
- `src/services/requirements.txt`: application and test dependencies.
- `src/guardrails.py`: shared report safety checks.
- `src/evaluation.py` and `run_evals.py`: offline captured-report evaluation and CLI.
- `tests/`: offline tests and synthetic evaluation cases.
- `tests/fixtures/`: synthetic captured reports.
- `pytest.ini`: pytest import-path configuration.
- `AGENTS.md`: repository guidelines.
- `docs/architecture.md`: orchestrator workflow and Mermaid architecture diagram.

## FastAPI interface

After installing `src/services/requirements.txt`, start the local API from the
repository root. FastAPI, Uvicorn, HTTPX, and pytest are already declared there.
Set `OPENAI_API_KEY` in the ignored `.env` or environment, and configure a model
available to your account:

```powershell
$env:OPENAI_MODEL = "your_available_model_id"
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000
```

Both `src.main:app` and `src.api:app` expose the same application.
The server loads the root `.env` at startup without overriding environment values.
`GET /health` returns `{"status":"ok"}` without credentials or model calls; it
checks liveness only. Open `http://127.0.0.1:8000/docs` for the request and response
schemas and an interactive request form.

`POST /analyse` accepts an object containing a nonempty `alerts` list with unique
IDs. Supply synthetic training data only; requests make live model calls:

```json
{
  "alerts": [
    {
      "id": "synthetic-1",
      "source": "training",
      "timestamp": "2026-01-01T12:00:00Z",
      "alert_type": "failed_login",
      "description": "Three unsuccessful sign-ins on a training account."
    }
  ]
}
```

For example, send the existing synthetic sample file from PowerShell:

```powershell
$alerts = @(Get-Content .\src\data\sample_alerts.json -Raw | ConvertFrom-Json)
$body = @{ alerts = $alerts } | ConvertTo-Json -Depth 20
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyse -ContentType "application/json" -Body $body
```

The response is `{"reports": [...]}`, containing one structured `SOCReport`
per alert in input order. Reports include severity, confidence, summary, evidence,
uncertainties, IOCs, techniques, recommendations, `requires_human_review=true`,
and `containment_status="not_performed"`. This endpoint calls advisory triage
only and exposes no containment execution or approval interface.

| HTTP status | Meaning |
| --- | --- |
| 422 | Malformed JSON, invalid alerts, empty batch, duplicate IDs, or unknown top-level fields. |
| 503 | Missing server configuration or upstream rate limit. |
| 502 | Model service failure or invalid generated report. |
| 504 | Upstream timeout or the 60-second workflow deadline. |
| 500 | Unexpected workflow failure. |

Failures return a `detail` field. Workflow exception text is never sent to clients.
Invalid SDK model output and exhausted agent turns return 502. For report
validation and unexpected failures, the Uvicorn terminal records the exception
type and code locations only, without exception messages or alert contents.
After changing server code, restart Uvicorn before retrying a request.
Batch analysis returns reports only when the entire workflow succeeds; earlier
model calls may already have occurred if a later alert fails.

The API owns HTTP validation and error translation. `src/models/api.py` reuses
`Alert` and `SOCReport` for the wire contracts. `src/agents/triage_agent.py` retains
agent orchestration, output guardrails, and human-review enforcement.

Run API tests or the entire offline suite without live credentials:

```powershell
python -m pytest tests/test_api.py
python -m pytest
git diff --check
```

API tests use FastAPI's TestClient with mocked triage and configuration loading;
they cover requests, serialization, errors, and deadline cancellation. The
existing workflow tests verify agent behavior and containment approval separately.

## Minimal alert triage

Run the local workflow from PowerShell after completing setup:

```powershell
$env:OPENAI_MODEL = "your_available_model_id"
python .\run_local.py
```

The runner loads `OPENAI_API_KEY` from the project `.env` or environment,
validates `src/data/sample_alerts.json` with `Alert`, and prints an indented JSON
list of SOC reports. It makes live model requests. Missing configuration,
invalid alerts, or triage failures produce an error on stderr and exit code 1.

`src/agents/triage_agent.py` exposes `triage_alerts`: pass one validated `Alert`
or a nonempty list and receive a list of `SOCReport` objects, one per alert.
`src/models/alert.py` defines the input; `src/models/report.py` defines the output.
Triage is the orchestrator: it optionally calls threat intelligence for IOC
context, offline investigation for batch correlations or process evidence, and
response for read-only next-step advice. It keeps control and owns the final
SOCReport. Simple alerts can skip specialists; there is no mandatory sequence.
See [the architecture diagram](docs/architecture.md) for the full flow.
Triage remains advisory. A separate, opt-in simulated containment workflow
is described below. Every report requires human review.
The model is instructed to use supplied evidence only and disclose that no
external lookup occurred. Structured output validates shape, not factual accuracy.
API or validation failures propagate to the caller instead of producing a fake report.

Lightweight guardrails reject blank or malformed alert inputs before model calls,
including mutated alert objects and duplicate batch IDs. Final reports separate
supplied `evidence` from required `uncertainties`, reject common speculative wording
in evidence, and carry a fixed `containment_status="not_performed"`. A conservative
text check rejects common containment language across report prose, including
quoted or negated matches. Unsafe reports fail validation instead of being printed.
These checks add no dependencies and do not prove that generated prose is factual.
See [guardrail protections and limits](docs/architecture.md#lightweight-triage-guardrails).

After installing the requirements above, set a model ID available to your account:

```powershell
$env:OPENAI_MODEL = "your_available_model_id"
```

From the project root, run this example in Python (or save it as `run_triage.py`
and run `python .\run_triage.py`). It loads the ignored `.env` for
`OPENAI_API_KEY` and makes a live model request:

```python
import asyncio
import os

from dotenv import load_dotenv

from src.agents.triage_agent import triage_alerts
from src.models.alert import Alert

load_dotenv()
alert = Alert(
    id="synthetic-1",
    source="training",
    timestamp="2026-01-01T12:00:00Z",
    alert_type="failed_login",
    description="Three unsuccessful sign-in attempts on a training account.",
)
reports = asyncio.run(triage_alerts(alert, model=os.environ["OPENAI_MODEL"]))
for report in reports:
    print(report.model_dump_json(indent=2))
```

Run the mocked tests without API credentials from the project root:

```powershell
python -m pytest
git diff --check
```

`pytest.ini` adds the repository root to Python's import path, so both
`pytest` and `python -m pytest` can import `src` and `run_local`. Use the
project virtual environment to ensure the correct dependencies are installed.

Tests cover single and multiple alerts, malformed input, invalid reports,
API failures, forced human review, and the specialist tool wiring. They do not measure
the model's assessment quality or guarantee that generated prose is factual.

## Evaluation runner

Run the deterministic evaluation suite without credentials or model calls:

```powershell
python .\run_evals.py --output docs/eval_example_result.json
python -m pytest tests/test_evaluation.py
```

`src/evaluation.py` checks structured `SOCReport` output, allowed severity,
finite confidence from 0 to 1, recorded tool source provenance, containment
safety, and nonblank evidence and uncertainty lists. Each check is reported
independently. Advisory triage must always report `not_performed`, require human
review, and pass the existing conservative containment prose check. This runner
never executes a containment action or grants approval.

`tests/eval_cases.json` holds synthetic alerts and an `expected_severity` field.
An analyst can set this to `low`, `medium`, `high`, or `critical`; use `null` until
labelled. The example labels are illustrative training judgements, not an
independently reviewed benchmark. Severity agreement is reported separately
from deterministic correctness and excludes unlabelled cases.

`tests/fixtures/eval_reports.json` contains hand-written example captures, not
live model results. To evaluate model behaviour, save one capture per case using
that same format, then run:

```powershell
python .\run_evals.py --reports path/to/captured_reports.json --output docs/eval_result.json
```

Each capture contains `case_id`, the original structured `report`,
`claimed_tool_sources` (all source labels claimed in the report, extracted by
a reviewer or capture adapter), and `observed_tool_sources` (labels from actual
tool results). Preserve failed/invalid reports for evaluation rather than fixing
them. Do not populate observed sources from the model's claims. This runner
compares those explicit labels; it cannot discover omitted claims or prove
arbitrary prose factual. The example captures have no tool claims or calls;
tests separately exercise fabricated source rejection. Capturing live SDK tool
traces and automatic prose attribution are not implemented here.

Exit codes: `0` means all deterministic checks passed, `1` means a check failed,
and `2` means invalid suite input or a file error. Duplicate, missing, and unknown
case IDs are rejected. A severity disagreement alone does not change the exit
code. No dependencies were added.

Expected results for the current four-case suite (the saved [earlier example](docs/eval_example_result.json) contains the original three cases):

| Case | Checks passed | Severity | Expected | Match |
| --- | --- | --- | --- | --- |
| few-failures | 6/6 | low | low | yes |
| repeated-failures | 6/6 | medium | medium | yes |
| process-review | 6/6 | medium | unlabelled | unlabelled |
| training-login-4 | 6/6 | low | low | yes |

Deterministic checks: 4/4 cases passed. Severity agreement: 3/3 labelled cases.
These numbers demonstrate the runner, not live model quality.

## Syntax verification

```powershell
python -c "import ast; from pathlib import Path; ast.parse(Path('check_models.py').read_text())"
git diff --check
```

The first command checks the script's Python syntax without calling the API.

## Offline investigation agent

`src/agents/investigation_agent.py` exposes `investigate_alerts(alerts)` for one
validated `Alert` or a nonempty list with unique IDs. It returns an
`InvestigationReport` containing pairwise correlations, a cautious narrative,
evidence-linked ATT&CK-style techniques, uncertainties, and required human review.
Use synthetic/local alerts only. This entry point runs entirely offline with no
model calls, credentials, new dependencies, or containment actions.

```python
from src.agents.investigation_agent import investigate_alerts
from src.models.alert import Alert

alert = Alert(
    id="synthetic-process", source="training",
    timestamp="2026-01-01T12:00:00Z", alert_type="process_start",
    description="PowerShell started on a training host.",
    hostname="training-host", raw_data={"process_name": "powershell.exe"},
)
print(investigate_alerts(alert).model_dump_json(indent=2))
```

Correlation uses exact shared hostnames, usernames, source IPs, or destination
IPs. Shared values do not prove causality. Supplied descriptions are explicitly
quoted as source claims; missing events are never filled in. Timezone-aware
timestamps order observations; missing timezones produce a limitation instead.
The deliberately small local mapping recognizes T1059.001 (Command and Scripting
Interpreter: PowerShell) only for `process_start` alerts with an explicit
`raw_data.process_name` of `powershell`, `powershell.exe`, `pwsh`, or `pwsh.exe`
(case-insensitive). Execution does not establish malicious intent. Descriptions,
severity labels, and unsupported behaviors alone produce no technique mapping.
The narrative is a conservative association hypothesis, not a confirmed attack
chain. Triage can call this helper as a tool using the original alert batch.

```powershell
python -m pytest tests/test_investigation_agent.py
python -m pytest
git diff --check
```

Tests use synthetic inputs and exercise related and unrelated alerts, evidence
requirements, malformed inputs, ambiguous timestamps, and instruction-like data.

## Advisory response agent

`src/agents/response_agent.py` exposes async `recommend_response(report, model=...)`
for one validated `SOCReport`. It makes a live model request and returns a
`ResponsePlan` from `src/models/response.py`. No new dependencies are required.
Triage can call this entry point with `read_only=True` for investigation advice;
in this mode a nonempty containment list is rejected. Standalone calls retain
the default advisory proposal behavior described below.

The structured output separates `investigate` (read-only evidence gathering)
from `containment` proposals. Each containment proposal includes a description,
rationale, proposed effect, and `requires_human_approval=True`. False approval
flags are rejected, and every plan requires human review. The agent has no tools
or handoffs and cannot execute containment or simulate execution. Approval
is handled by the separate simulation workflow described below. Classification of generated prose still
requires analyst review; schema validation does not guarantee semantic accuracy.
Model and output validation failures propagate to the caller.

After setup, use the returned triage report in an async workflow:

```python
from src.agents.response_agent import recommend_response

# reports and model come from your existing triage workflow.
plan = await recommend_response(reports[0], model=model)
print(plan.model_dump_json(indent=2))
```

Run deterministic mocked tests without credentials:

```powershell
python -m pytest tests/test_response_agent.py
python -m pytest
git diff --check
```

Tests cover separated recommendations, approval enforcement, empty containment,
invalid inputs and outputs, SDK failures, and absence of execution tools/handoffs.

## Project status

The core learning prototype is implemented: advisory triage, specialist tools, a local API, approval-gated simulation, offline tests, and captured-report evaluations. Uses synthetic data only and requires analyst review. Offline evaluation results do not establish live model quality.

## Human-approved simulated host isolation

`src/tools/containment.py` defines `request_host_isolation(hostname, reason)`
using `@function_tool(needs_approval=True)`. It only returns a SIMULATED message:
it never contacts an EDR platform or changes host or network state. Both inputs
must be nonempty. Use synthetic training hosts only.

`src/agents/containment_agent.py` provides a separate, opt-in workflow.
`run_host_isolation` starts a model run, then `review_containment` displays each
paused tool call's actual arguments and simulated effect. Only typing exactly
`APPROVE` approves that call; other input or an unavailable console rejects it.
Approval is scoped to the individual call, with no blanket approval. Subsequent
calls require another review. Triage and the response specialist remain advisory.

After setup, save this as `run_simulation.py` at the repository root and run
`python .\run_simulation.py` with `OPENAI_MODEL` configured:

```python
import asyncio
import os
from dotenv import load_dotenv
from src.agents.containment_agent import run_host_isolation

load_dotenv()
result = asyncio.run(run_host_isolation(
    "training-host", "Synthetic alert requires analyst review",
    model=os.environ["OPENAI_MODEL"],
))
print(result.final_output)
```

Model calls use your configured API credentials; the containment tool itself
has no network code. No new dependencies are required. Verified with
`openai-agents` 0.23.1. Approval is enforced by `Runner`, not by directly calling
the tool's low-level `on_invoke_tool` callback; use the workflow above.
The implementation follows the official
[OpenAI human-review pattern](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals):
inspect `result.interruptions`, obtain human approval, call
`result.to_state()`, approve or reject each item, and resume the same state.

```powershell
python -m pytest tests/test_containment.py
python -m pytest
git diff --check
```

Tests use the real SDK runner with an offline fake model. They verify pausing
without execution, remaining paused without a decision, rejection, explicit
per-call approval, fail-closed console input, and malformed arguments. Network
connections are blocked during the tests; no API credentials are required.
## Synthetic threat intelligence tool

`src/tools/threat_intel.py` exposes `threat_intel`, an Agents SDK
`@function_tool`. The decorator builds the input schema from the signature
and descriptions from the docstring. Pass it in an agent's `tools=[threat_intel]`
list to enable it. The specialist uses this tool; triage calls the specialist as a tool.

The local fake database marks 203.0.113.10 suspicious (confidence 0.9) and
198.51.100.20 benign (confidence 0.8). Unlisted valid IPv4 or IPv6 addresses
return unknown with confidence 0.0; malformed addresses return invalid with
confidence 0.0. Every result contains reputation, confidence,
source="synthetic-local-db", and a short note. Confidence values are invented
training values on a 0 to 1 scale, not measured probabilities. Unknown does not
mean safe. Synthetic verdicts say nothing about real-world reputation.

The plain lookup needs no model, credentials, or internet connection:

```powershell
python -c "from src.tools.threat_intel import lookup_ip_reputation; print(lookup_ip_reputation('203.0.113.10'))"
python -m pytest tests/test_threat_intel.py
python -m pytest
git diff --check
```

Dependencies are already in src/services/requirements.txt. Tests cover known,
unknown, invalid, and IPv6 inputs, deterministic results, protection against
result mutation, and SDK tool invocation with network access blocked.
No VirusTotal or paid external reputation API is used.

## Threat-intelligence specialist

`src/agents/threat_intel_agent.py` exposes `create_threat_intel_agent(model=...)`
and `create_threat_intel_tool(model=...)`. Triage uses the SDK `Agent.as_tool()`
pattern: it receives the specialist evidence and continues producing `SOCReport`.
A handoff would transfer control to the specialist, which is inappropriate here.

The specialist has only the approved synthetic `threat_intel` IP lookup.
It is instructed to inspect supplied IOCs, report unsupported hashes/domains/URLs,
and distinguish unknown, invalid, and failed lookups. `ThreatIntelEvidence`
contains IOC findings (IOC, status, source, confidence, note) and limitations;
it has no incident verdict or severity. Results are validated and serialized
as JSON before returning to triage. Specialist run or output-validation failures
propagate rather than producing replacement evidence.

No new dependencies are required. Model calls remain live when running
`run_local.py`; the reputation lookup remains local and synthetic. Specialist
calls can add model requests and latency. Structured validation enforces shape,
not factual accuracy or guaranteed lookup coverage; a human must review evidence.

```powershell
python -m pytest tests/test_threat_intel_agent.py tests/test_triage_agent.py
python -m pytest
git diff --check
```

Specialist tests mock model calls and check the fixed tool allowlist, absence of
handoffs, evidence serialization, rejection of verdict fields, and propagation
of failures. They do not establish how a live model will interpret an incident.

## Suggestions for further development

- Replace the fake IP reputation database with a legitimate threat-intelligence integration while keeping API keys secret.
- Add a real MITRE ATT&CK knowledge source or curated local mapping, expanding the current small PowerShell mapping.
- Add file, hash, and domain enrichment.
- Add conversation/session state for an analyst follow-up workflow.
- Add MCP only when you can explain why it is preferable to a normal function/API integration.
- Containerise the API with Docker.
- Add CI so GitHub runs tests automatically on pushes and pull requests.
- Add a small web dashboard showing incident severity, evidence, and approval state.
- Compare single-agent versus multi-agent quality, cost, and latency using the evaluation set.
- Document the threat model, trust boundaries, and prompt-injection considerations.
