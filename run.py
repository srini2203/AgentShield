"""Entrypoint to start the AgentShield FastAPI server via Uvicorn."""

import os

import uvicorn


def main() -> None:
    """Start the FastAPI application with Uvicorn."""
    host = os.environ.get("AGENTSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENTSHIELD_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
