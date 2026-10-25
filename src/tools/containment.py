"""Simulation-only containment; approval is enforced by the SDK runner."""

from agents import function_tool


@function_tool(needs_approval=True, failure_error_function=None)
def request_host_isolation(hostname: str, reason: str) -> str:
    """Simulate host isolation after human approval, without contacting any EDR.

    Args:
        hostname: Synthetic training host proposed for isolation.
        reason: Evidence-based reason for the simulated isolation.
    """
    if not hostname.strip() or not reason.strip():
        raise ValueError("Hostname and reason must be nonempty.")
    return (
        f"SIMULATED: Host isolation for {hostname!r}. Reason: {reason!r}. "
        "No EDR platform was contacted and no host or network state was changed."
    )
