"""Small, deterministic checks at the advisory triage boundary."""

import re

from src.models.report import SOCReport


# Conservative vocabulary check: even quoted or negated matches are rejected.
# Triage has no containment tools, so it need not narrate containment at all.
CONTAINMENT_LANGUAGE = re.compile(
    r"\b(?:containment|isolat\w*|quarantin\w*)\b"
    r"|\b(?:disabl\w*|revok\w*|block\w*)\b[^.!?\n]{0,60}"
    r"\b(?:account|user|access|traffic|connection|ip|session|credential|token)s?\b"
    r"|\b(?:account|user|access|traffic|connection|ip|session|credential|token)s?\b"
    r"[^.!?\n]{0,60}\b(?:disabl\w*|revok\w*|block\w*)\b",
    re.IGNORECASE,
)
SPECULATIVE_EVIDENCE = re.compile(
    r"\b(?:may|might|possibly|possible|probably|likely|hypothesis|inferred|suspected)\b",
    re.IGNORECASE,
)


def validate_final_report(report: SOCReport) -> None:
    """Reject unsafe prose; never silently rewrite a failed assessment."""
    if not report.evidence or any(not item.strip() for item in report.evidence):
        raise ValueError("Final reports must include nonblank supplied evidence.")
    if not report.uncertainties or any(not item.strip() for item in report.uncertainties):
        raise ValueError("Final reports must disclose nonblank uncertainties separately.")
    if any(SPECULATIVE_EVIDENCE.search(item) for item in report.evidence):
        raise ValueError("Put hypotheses in uncertainties, not evidence.")

    prose = [report.summary, *report.evidence, *report.uncertainties,
             *report.iocs, *report.attack_techniques, *report.recommended_actions]
    if any(CONTAINMENT_LANGUAGE.search(item) for item in prose):
        raise ValueError("Final advisory reports must not narrate containment actions.")
