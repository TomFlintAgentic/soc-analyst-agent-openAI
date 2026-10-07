import asyncio
import json
import os
from pathlib import Path
import sys

from dotenv import load_dotenv
from pydantic import ValidationError

from src.agents.triage_agent import triage_alerts
from src.models.alert import Alert


PROJECT_ROOT = Path(__file__).resolve().parent
ALERTS_PATH = PROJECT_ROOT / "src" / "data" / "sample_alerts.json"


async def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        print("Error: OPENAI_API_KEY is missing. Set it in the project .env or environment.", file=sys.stderr)
        return 1
    model = os.environ.get("OPENAI_MODEL", "").strip()
    if not model:
        print("Error: Set OPENAI_MODEL to a model ID available to your account.", file=sys.stderr)
        return 1

    try:
        data = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or not data:
            raise ValueError("Expected one alert object or a nonempty list of alerts.")
        alerts = [Alert.model_validate(item) for item in data]
    except (OSError, ValueError) as error:
        if isinstance(error, ValidationError):
            detail = "; ".join(
                f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}"
                for issue in error.errors(include_input=False)
            )
        else:
            detail = str(error)
        print(f"Error loading {ALERTS_PATH}: {detail}", file=sys.stderr)
        return 1

    try:
        reports = await triage_alerts(alerts, model=model)
    except Exception as error:
        # Avoid printing SDK exception text, which may contain request data.
        print(
            f"Error: Triage failed ({type(error).__name__}). "
            "Check your credentials, model access, network, and report validation.",
            file=sys.stderr,
        )
        return 1

    print(json.dumps([report.model_dump(mode="json") for report in reports], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
