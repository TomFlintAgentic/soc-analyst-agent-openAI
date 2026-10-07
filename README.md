# OpenAI SOC Analyst Agent

A learning and portfolio project that demonstrates an AI-assisted SOC triage workflow built with Python and the OpenAI Agents SDK.

> Status: work in progress.  Uses synthetic security data only.

## Setup

Run these commands in PowerShell from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\src\services\requirements.txt
```

Create a local `.env` file containing your API key:

```dotenv
OPENAI_API_KEY=your_api_key_here
```

The `.env` file and `.venv` directory are ignored by Git. Never commit credentials.

## Check available models

```powershell
python .\check_models.py
```

This script loads the local environment variables and prints the model IDs returned by the OpenAI API for your credentials. It requires internet access and a valid API key.

## Project structure

- `check_models.py`: utility for listing available models.
- `run_local.py`: loads synthetic alerts, validates them, and prints SOC reports.
- `src/data/sample_alerts.json`: synthetic inputs for the local runner.
- `src/agents/`: package reserved for agent code.
- `src/models/`: package reserved for data models.
- `src/tools/`: package reserved for agent tools.
- `src/services/`: package reserved for services; currently holds `requirements.txt`.
- `AGENTS.md`: repository guidelines.

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
There are no tools or containment actions. Every report requires human review.
The model is instructed to use supplied evidence only and disclose that no
external lookup occurred. Structured output validates shape, not factual accuracy.
API or validation failures propagate to the caller instead of producing a fake report.

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

Run the mocked tests without API credentials:

```powershell
python -m pytest
git diff --check
```

Tests cover single and multiple alerts, malformed input, invalid reports,
API failures, forced human review, and the absence of tools. They do not measure
the model's assessment quality or guarantee that generated prose is factual.

## Syntax verification

```powershell
python -c "import ast; from pathlib import Path; ast.parse(Path('check_models.py').read_text())"
git diff --check
```

The first command checks the script's Python syntax without calling the API.

## Project status

Work in progress: a learning and portfolio project for an AI-assisted
SOC analyst. Uses synthetic security data only.