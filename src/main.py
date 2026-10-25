"""Server entry point; HTTP routes and agent logic live in separate modules."""

from src.api import app

__all__ = ["app"]
