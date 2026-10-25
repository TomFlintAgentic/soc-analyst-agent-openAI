"""Deterministic synthetic IP reputation lookup; no external services."""

from ipaddress import ip_address as parse_ip_address

from agents import function_tool


SOURCE = "synthetic-local-db"
# Documentation-only IPs with invented verdicts for training.
FAKE_REPUTATION_DB = {
    "203.0.113.10": {
        "reputation": "suspicious",
        "confidence": 0.9,
        "source": SOURCE,
        "note": "Synthetic suspicious training entry; not real threat intelligence.",
    },
    "198.51.100.20": {
        "reputation": "benign",
        "confidence": 0.8,
        "source": SOURCE,
        "note": "Synthetic benign training entry; not proof of real-world safety.",
    },
}


def lookup_ip_reputation(ip_address: str) -> dict[str, str | float]:
    """Look up a literal IPv4 or IPv6 address in the fake database."""
    try:
        if not isinstance(ip_address, str):
            raise ValueError("An IP address must be a string.")
        normalized_ip = str(parse_ip_address(ip_address))
    except ValueError:
        return {
            "reputation": "invalid",
            "confidence": 0.0,
            "source": SOURCE,
            "note": "Provide a valid IPv4 or IPv6 address literal.",
        }

    if normalized_ip in FAKE_REPUTATION_DB:
        # A copy prevents callers from changing future lookup results.
        return FAKE_REPUTATION_DB[normalized_ip].copy()

    return {
        "reputation": "unknown",
        "confidence": 0.0,
        "source": SOURCE,
        "note": "No synthetic entry exists; unknown does not mean safe.",
    }


@function_tool
def threat_intel(ip_address: str) -> dict[str, str | float]:
    """Return fake local reputation only, never real-world threat intelligence.

    Args:
        ip_address: A literal IPv4 or IPv6 address to look up locally.

    Returns:
        Reputation, synthetic confidence from 0 to 1, source, and a short note.
        Unlisted IPs are unknown; malformed addresses are invalid.
    """
    return lookup_ip_reputation(ip_address)
