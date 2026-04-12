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
    
    # MCP Interfaces:
    - POST /mcp: Simplified MCP interface (existing)
    - POST /mcp-standard/*: Standard MCP protocol (new)
    - WS /mcp-standard/ws: Standard MCP WebSocket (new)

Usage:
    # Development (with auto-reload):
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

    # Production:
    uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 4

    # Or run directly:
    python -m server.app
"""

import gradio as gr
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse

try:
    from openenv.core.env_server.http_server import create_fastapi_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required. Install dependencies with '\n    uv sync\n'"
    ) from e

try:
    from ..models import NetworkForensicsAction, NetworkForensicsObservation
    from .gradio_ui import create_demo
    from .mcp_network_forensics_environment import NetworkForensicsMCPEnv
except ImportError:
    from models import NetworkForensicsAction, NetworkForensicsObservation
    from server.gradio_ui import create_demo
    from server.mcp_network_forensics_environment import NetworkForensicsMCPEnv


# ---------------------------------------------------------------------------
# OpenEnv API — exposes /reset, /step, /state, /schema, /ws
# PLUS /mcp (HTTP POST + WebSocket) for MCP tool access
# AND /mcp-standard/* for full MCP protocol compliance
# ---------------------------------------------------------------------------
app = create_fastapi_app(
    NetworkForensicsMCPEnv,
    NetworkForensicsAction,
    NetworkForensicsObservation,
    max_concurrent_envs=4,  # allow up to 4 concurrent WebSocket sessions
)

# ---------------------------------------------------------------------------
# Standard MCP Server — routes registered directly on the main app so they
# take priority over Gradio's catch-all mount at "/".
# Using app.mount() for a sub-app does NOT work because Gradio's mount
# at "/" swallows all paths before sub-app mounts get a chance.
# ---------------------------------------------------------------------------
from server.mcp_standard_server import register_mcp_routes

register_mcp_routes(app)


@app.get("/health", include_in_schema=False)
async def health_check() -> JSONResponse:
    """Liveness probe for Hugging Face Spaces and Docker health checks."""
    return JSONResponse({"status": "ok", "service": "network-forensics-env"})


@app.get("/mcp-info", include_in_schema=False)
async def mcp_info() -> JSONResponse:
    """Information about available MCP interfaces."""
    return JSONResponse({
        "mcp_interfaces": {
            "simplified": {
                "endpoint": "/mcp",
                "description": "Simplified MCP interface (HTTP POST + WebSocket)",
                "compatibility": "OpenEnv custom protocol"
            },
            "standard": {
                "endpoint": "/mcp-standard",
                "description": "Full MCP protocol compliance (JSON-RPC 2.0)",
                "compatibility": "Claude Desktop, Cursor, standard MCP clients",
                "methods": ["initialize", "tools/list", "tools/call"]
            }
        },
        "note": "POST JSON-RPC 2.0 to /mcp-standard for standard MCP clients"
    })


@app.get("/web", include_in_schema=False)
async def web_redirect() -> RedirectResponse:
    return RedirectResponse(url="/")


@app.get("/web/", include_in_schema=False)
async def web_redirect_slash() -> RedirectResponse:
    return RedirectResponse(url="/")


# Mount the custom analyst UI at the root path for Hugging Face Spaces. The
# explicit API routes above (including /mcp-standard) take precedence because
# FastAPI routes are checked before Starlette mounts.
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
