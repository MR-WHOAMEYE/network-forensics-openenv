# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application for the Network Forensics Environment.

This module creates an HTTP server that exposes the NetworkForensicsEnvironment
over HTTP and WebSocket endpoints, compatible with EnvClient.

Endpoints:
    - POST /reset: Reset the environment
    - POST /step: Execute an action
    - GET /state: Get current environment state
    - GET /schema: Get action/observation schemas
    - WS /ws: WebSocket endpoint for persistent sessions

Usage:
    # Development (with auto-reload):
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

    # Production:
    uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 4

    # Or run directly:
    python -m server.app
"""

import gradio as gr
from fastapi.responses import RedirectResponse

try:
    from openenv.core.env_server.http_server import create_fastapi_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. Install dependencies with '\n    uv sync\n'"
    ) from e

try:
    from ..models import NetworkForensicsAction, NetworkForensicsObservation
    from .gradio_ui import create_demo
    from .network_forensics_environment import NetworkForensicsEnvironment
except ImportError:
    from models import NetworkForensicsAction, NetworkForensicsObservation
    from server.gradio_ui import create_demo
    from server.network_forensics_environment import NetworkForensicsEnvironment


# Create the OpenEnv API app first so its routes stay available.
app = create_fastapi_app(
    NetworkForensicsEnvironment,
    NetworkForensicsAction,
    NetworkForensicsObservation,
    max_concurrent_envs=1,  # increase this number to allow more concurrent WebSocket sessions
)


@app.get("/web", include_in_schema=False)
async def web_redirect() -> RedirectResponse:
    return RedirectResponse(url="/")


@app.get("/web/", include_in_schema=False)
async def web_redirect_slash() -> RedirectResponse:
    return RedirectResponse(url="/")


# Mount the custom analyst UI at the root path for Hugging Face Spaces. The
# explicit OpenEnv API routes above continue to take precedence.
app = gr.mount_gradio_app(app, create_demo(), path="/")


def serve(host: str = "0.0.0.0", port: int = 8000):
    """
    Entry point for direct execution via uv run or python -m.

    This function enables running the server without Docker:
        uv run --project . server
        uv run --project . server --port 8001
        python -m network_forensics.server.app

    Args:
        host: Host address to bind to (default: "0.0.0.0")
        port: Port number to listen on (default: 8000)

    For production deployments, consider using uvicorn directly with
    multiple workers:
        uvicorn network_forensics.server.app:app --workers 4
    """
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def main() -> None:
    """Validator-friendly entrypoint for direct execution."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
