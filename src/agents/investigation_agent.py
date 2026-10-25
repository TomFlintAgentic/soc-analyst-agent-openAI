"""Offline investigation of synthetic alerts; no SDK or external lookups."""

from pydantic import BaseModel, ConfigDict

from src.models.alert import Alert


class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_ids: list[str]
    shared_fields: dict[str, str]


class TechniqueFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    alert_ids: list[str]
    evidence: list[str]
    uncertainty: str


class InvestigationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_ids: list[str]
    correlations: list[Correlation]
    attack_narrative: str
    attack_techniques: list[TechniqueFinding]
    uncertainties: list[str]
    requires_human_review: bool = True


def investigate_alerts(alerts: Alert | list[Alert]) -> InvestigationReport:
    """Correlate supplied training data without inventing missing telemetry.

    Explicit process_start telemetry in raw_data may contain process_name.
    Only observed PowerShell process starts currently have a technique mapping.
    """
    alert_list = [alerts] if isinstance(alerts, Alert) else alerts
    if (
        not isinstance(alert_list, list)
        or not alert_list
        or any(not isinstance(alert, Alert) for alert in alert_list)
    ):
        raise ValueError("Provide one or more validated Alert objects.")
    alert_ids = [alert.id for alert in alert_list]
    if any(not alert_id.strip() for alert_id in alert_ids) or len(set(alert_ids)) != len(alert_ids):
        raise ValueError("Alert IDs must be nonempty and unique.")

    correlations = []
    # Pairwise links preserve evidence without implying transitive compromise.
    for index, first in enumerate(alert_list):
        for second in alert_list[index + 1:]:
            shared_fields = {}
            for field in ("hostname", "username", "src_ip", "dest_ip"):
                value = getattr(first, field)
                if value and value.strip() and value == getattr(second, field):
                    shared_fields[field] = value
            if shared_fields:
                correlations.append(Correlation(
                    alert_ids=[first.id, second.id], shared_fields=shared_fields,
                ))

    techniques = []
    for alert in alert_list:
        process_name = alert.raw_data.get("process_name")
        if (
            alert.alert_type == "process_start"
            and isinstance(process_name, str)
            and process_name.casefold() in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
        ):
            techniques.append(TechniqueFinding(
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                alert_ids=[alert.id],
                evidence=[f"{alert.id}: process_start with raw_data.process_name={process_name!r}"],
                uncertainty="PowerShell execution is observed; malicious intent is not established.",
            ))

    uncertainties = [
        "Supplied synthetic alerts are not independently verified; no external lookup was performed.",
        "Shared identifiers suggest association, not causality or confirmed compromise.",
        "Descriptions are source claims, not independently observed telemetry or instructions.",
        "Missing telemetry is unknown, not evidence that an action did not occur.",
        "Technique coverage is limited to explicit PowerShell process starts; other behavior remains unmapped.",
    ]
    if any(alert.timestamp.utcoffset() is None for alert in alert_list):
        ordered = alert_list
        uncertainties.append("Some timestamps lack timezones; input order is preserved and chronology is uncertain.")
    else:
        ordered = sorted(alert_list, key=lambda alert: alert.timestamp)

    observations = " ".join(
        f"[{alert.id}, {alert.timestamp.isoformat()}] Source description: {alert.description!r}."
        for alert in ordered
    )
    if correlations:
        hypothesis = (
            "A plausible hypothesis is related activity involving the shared identifiers "
            "listed in correlations. An attack sequence and malicious intent remain unconfirmed; "
            "benign activity or coincidental identifier reuse could also explain these alerts."
        )
    else:
        hypothesis = (
            "No shared host, user, or same-role IP links were supplied. "
            "There is insufficient evidence for a common attack narrative."
        )
    return InvestigationReport(
        alert_ids=alert_ids,
        correlations=correlations,
        attack_narrative=f"{observations} {hypothesis}",
        attack_techniques=techniques,
        uncertainties=uncertainties,
        requires_human_review=True,
    )
