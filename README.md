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
- `src/agents/`: package reserved for agent code.
- `src/models/`: package reserved for data models.
- `src/tools/`: package reserved for agent tools.
- `src/services/`: package reserved for services; currently holds `requirements.txt`.
- `AGENTS.md`: repository guidelines.

## Verification

```powershell
python -c "import ast; from pathlib import Path; ast.parse(Path('check_models.py').read_text())"
git diff --check
```

The first command checks the script's Python syntax without calling the API. No automated test suite exists yet.
