"""Small HTTP adapter for the advisory SOC workflow."""

import asyncio
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
import traceback

from agents.exceptions import MaxTurnsExceeded, ModelBehaviorError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from openai import APIError, APITimeoutError, RateLimitError

from src.agents.triage_agent import triage_alerts
from src.models.api import AnalyseRequest, AnalyseResponse, HealthResponse


ANALYSIS_TIMEOUT_SECONDS = 60
PROJECT_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger("uvicorn.error")


def log_workflow_failure(error: Exception) -> None:
    """Keep useful code locations without exception text, source lines, or locals."""
    locations = [
        f"{Path(frame.filename).name}:{frame.lineno} in {frame.name}"
        for frame in traceback.extract_tb(error.__traceback__)
    ]
    logger.error("SOC workflow failed (%s); locations: %s",
                 type(error).__name__, " -> ".join(locations))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Existing environment values take precedence over the ignored local file.
    load_dotenv(PROJECT_ROOT / ".env")
    yield


app = FastAPI(title="Synthetic SOC analysis", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness only: does not call the model or require credentials."""
    return HealthResponse()


@app.post("/analyse", response_model=AnalyseResponse)
async def analyse(request: AnalyseRequest) -> AnalyseResponse:
    """Analyse synthetic alerts; the workflow owns all agent decisions."""
    model = os.environ.get("OPENAI_MODEL", "").strip()
    if not os.environ.get("OPENAI_API_KEY", "").strip() or not model:
        raise HTTPException(
            status_code=503,
            detail="Analysis is unavailable. Configure OPENAI_API_KEY and OPENAI_MODEL on the server.",
        )

    try:
        reports = await asyncio.wait_for(
            triage_alerts(request.alerts, model=model),
            timeout=ANALYSIS_TIMEOUT_SECONDS,
        )
        return AnalyseResponse(reports=reports)
    except (TimeoutError, APITimeoutError) as error:
        raise HTTPException(status_code=504, detail="Analysis timed out. Try again later.") from error
    except RateLimitError as error:
        raise HTTPException(
            status_code=503, detail="Model service is rate limited. Try again later.",
        ) from error
    except APIError as error:
        raise HTTPException(
            status_code=502, detail="Model service request failed. Check server credentials and model access.",
        ) from error
    except (ValueError, ModelBehaviorError, MaxTurnsExceeded) as error:
        # Input was validated above; these failures concern generated output.
        log_workflow_failure(error)
        raise HTTPException(
            status_code=502, detail="The workflow did not produce a valid advisory report.",
        ) from error
    except Exception as error:
        # Never return exception text: it can contain credentials or request data.
        log_workflow_failure(error)
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly.") from error
