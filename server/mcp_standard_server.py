"""
Standard MCP (Model Context Protocol) Server for Network Forensics Environment.

This module provides a full MCP-compliant server that implements the complete
MCP lifecycle including initialize, tool discovery, and proper protocol handling.
It coexists with the existing simplified MCP interface.

Usage:
    # Start the standard MCP server
    python -m server.mcp_standard_server
    
    # Or integrate with main app
    from server.mcp_standard_server import create_standard_mcp_app
    app.mount("/mcp-standard", create_standard_mcp_app())
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import the environment and models
try:
    from ..models import NetworkForensicsAction, NetworkForensicsObservation
    from .network_forensics_environment import NetworkForensicsEnvironment
except ImportError:
    from models import NetworkForensicsAction, NetworkForensicsObservation
    from server.network_forensics_environment import NetworkForensicsEnvironment


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# MCP Protocol Models
class MCPInitializeRequest(BaseModel):
    protocolVersion: str = "2024-11-05"
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    clientInfo: Dict[str, Any] = Field(default_factory=dict)


class MCPInitializeResponse(BaseModel):
    protocolVersion: str = "2024-11-05"
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    serverInfo: Dict[str, Any] = Field(default_factory=dict)


class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]


class MCPToolsListResponse(BaseModel):
    tools: List[MCPTool]


class MCPCallToolRequest(BaseModel):
    name: str
    arguments: Dict[str, Any]


class MCPCallToolResponse(BaseModel):
    content: List[Dict[str, Any]]
    isError: bool = False


class MCPErrorResponse(BaseModel):
    error: Dict[str, Any]


class NetworkForensicsMCPServer:
    """Standard MCP-compliant server for network forensics environment."""
    
    def __init__(self, task_id: str = "easy"):
        self.task_id = task_id
        self.env: Optional[NetworkForensicsEnvironment] = None
        self.session_id = str(uuid4())
        self.logger = logger
        
    def initialize(self, request: MCPInitializeRequest) -> MCPInitializeResponse:
        """Initialize the MCP server and environment."""
        try:
            self.env = NetworkForensicsEnvironment(task_id=self.task_id)
            self.logger.info(f"MCP server initialized with task: {self.task_id}")
            
            return MCPInitializeResponse(
                protocolVersion="2024-11-05",
                capabilities={
                    "tools": {
                        "listChanged": False
                    },
                    "resources": {
                        "subscribe": False,
                        "listChanged": False
                    }
                },
                serverInfo={
                    "name": "network-forensics-mcp",
                    "version": "1.0.0",
                    "description": "Network forensics analysis environment with MCP support"
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize MCP server: {e}")
            raise HTTPException(status_code=500, detail=f"Initialization failed: {str(e)}")
    
    def list_tools(self) -> MCPToolsListResponse:
        """List all available MCP tools."""
        tools = [
            MCPTool(
                name="reset_env",
                description="Start a new investigation episode with fresh network traffic",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "enum": ["easy", "medium", "hard"],
                            "description": "Difficulty level for the investigation",
                            "default": "easy"
                        }
                    }
                }
            ),
            MCPTool(
                name="get_status",
                description="Get current investigation status and progress",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            MCPTool(
                name="inspect_packet",
                description="Reveal the full payload of a packet for analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "packet_id": {
                            "type": "string",
                            "description": "The packet ID to inspect (e.g., 'pkt_0008')"
                        }
                    },
                    "required": ["packet_id"]
                }
            ),
            MCPTool(
                name="flag_as_suspicious",
                description="Flag a packet as malicious traffic",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "packet_id": {
                            "type": "string",
                            "description": "The packet ID to flag as suspicious"
                        }
                    },
                    "required": ["packet_id"]
                }
            ),
            MCPTool(
                name="group_into_session",
                description="Group related packets into a named attack session",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {
                            "type": "string",
                            "description": "Descriptive name for the session"
                        },
                        "packet_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of packet IDs belonging to this session"
                        }
                    },
                    "required": ["session_name", "packet_ids"]
                }
            ),
            MCPTool(
                name="tag_pattern",
                description="Tag a session with an attack family classification",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {
                            "type": "string",
                            "description": "Name of the session to tag"
                        },
                        "pattern_type": {
                            "type": "string",
                            "enum": [
                                "ddos", "dos_hulk", "dos_slowloris", "dos_goldeneye",
                                "dos_slowhttptest", "heartbleed", "web_xss",
                                "web_sql_injection", "web_bruteforce", "c2",
                                "exfiltration", "scan", "lateral"
                            ],
                            "description": "Attack pattern type"
                        }
                    },
                    "required": ["session_name", "pattern_type"]
                }
            ),
            MCPTool(
                name="identify_entry_point",
                description="Identify the initial compromise packet",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "claimed_entry_point": {
                            "type": "string",
                            "description": "Packet ID of the suspected entry point"
                        }
                    },
                    "required": ["claimed_entry_point"]
                }
            ),
            MCPTool(
                name="submit_report",
                description="Submit final incident report for scoring",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_summary": {
                            "type": "string",
                            "description": "Comprehensive incident report text"
                        },
                        "claimed_entry_point": {
                            "type": "string",
                            "description": "Optional packet ID for suspected entry point"
                        }
                    },
                    "required": ["incident_summary"]
                }
            )
        ]
        
        return MCPToolsListResponse(tools=tools)
    
    def call_tool(self, request: MCPCallToolRequest) -> MCPCallToolResponse:
        """Execute a specific MCP tool."""
        if not self.env:
            return MCPCallToolResponse(
                content=[{"type": "text", "text": "Environment not initialized. Call initialize first."}],
                isError=True
            )
        
        try:
            tool_name = request.name
            arguments = request.arguments
            
            self.logger.info(f"Calling tool: {tool_name} with args: {arguments}")
            
            if tool_name == "reset_env":
                return self._handle_reset_env(arguments)
            elif tool_name == "get_status":
                return self._handle_get_status()
            elif tool_name == "inspect_packet":
                return self._handle_inspect_packet(arguments)
            elif tool_name == "flag_as_suspicious":
                return self._handle_flag_as_suspicious(arguments)
            elif tool_name == "group_into_session":
                return self._handle_group_into_session(arguments)
            elif tool_name == "tag_pattern":
                return self._handle_tag_pattern(arguments)
            elif tool_name == "identify_entry_point":
                return self._handle_identify_entry_point(arguments)
            elif tool_name == "submit_report":
                return self._handle_submit_report(arguments)
            else:
                return MCPCallToolResponse(
                    content=[{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    isError=True
                )
                
        except Exception as e:
            self.logger.error(f"Tool execution failed: {e}")
            return MCPCallToolResponse(
                content=[{"type": "text", "text": f"Tool execution failed: {str(e)}"}],
                isError=True
            )
    
    def _handle_reset_env(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle reset_env tool call."""
        task_id = arguments.get("task_id", "easy")
        self.task_id = task_id
        
        # Reset the environment
        obs = self.env.reset(task_id=task_id)
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Environment reset with task: {task_id}\n"
                       f"Total packets: {obs.total_packets}\n"
                       f"Max steps: {obs.steps_remaining}"
            }]
        )
    
    def _handle_get_status(self) -> MCPCallToolResponse:
        """Handle get_status tool call."""
        state = self.env.state
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Step: {state.step_count}\n"
                       f"Steps remaining: {max(0, self.env._max_steps - state.step_count)}\n"
                       f"Flagged packets: {len(self.env._flagged_packets)}\n"
                       f"Grouped sessions: {len(self.env._grouped_sessions)}\n"
                       f"Tagged patterns: {len(self.env._tagged_patterns)}\n"
                       f"Entry point: {self.env._claimed_entry_point or 'None'}"
            }]
        )
    
    def _handle_inspect_packet(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle inspect_packet tool call."""
        packet_id = arguments["packet_id"]
        
        # Create action and execute
        action = NetworkForensicsAction(
            action_type="inspect_packet",
            packet_id=packet_id
        )
        
        obs = self.env.step(action)
        
        # Find the inspected packet
        packet_data = None
        for packet in obs.visible_packets:
            if packet.packet_id == packet_id:
                packet_data = packet.model_dump()
                break
        
        if packet_data:
            return MCPCallToolResponse(
                content=[{
                    "type": "text",
                    "text": f"Packet {packet_id} inspected:\n"
                           f"Source: {packet_data['src_ip']}:{packet_data['src_port']}\n"
                           f"Destination: {packet_data['dst_ip']}:{packet_data['dst_port']}\n"
                           f"Protocol: {packet_data['protocol']}\n"
                           f"Payload preview: {packet_data['payload_preview'][:100]}...\n"
                           f"Reward: {obs.reward}"
                }]
            )
        else:
            return MCPCallToolResponse(
                content=[{"type": "text", "text": f"Packet {packet_id} not found"}],
                isError=True
            )
    
    def _handle_flag_as_suspicious(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle flag_as_suspicious tool call."""
        packet_id = arguments["packet_id"]
        
        action = NetworkForensicsAction(
            action_type="flag_as_suspicious",
            packet_id=packet_id
        )
        
        obs = self.env.step(action)
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Packet {packet_id} flagged as suspicious.\n"
                       f"Total flagged: {len(obs.flagged_packet_ids)}\n"
                       f"Reward: {obs.reward}"
            }]
        )
    
    def _handle_group_into_session(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle group_into_session tool call."""
        session_name = arguments["session_name"]
        packet_ids = arguments["packet_ids"]
        
        action = NetworkForensicsAction(
            action_type="group_into_session",
            session_name=session_name,
            packet_ids=packet_ids
        )
        
        obs = self.env.step(action)
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Created session: {session_name}\n"
                       f"Packets grouped: {len(packet_ids)}\n"
                       f"Total sessions: {len(obs.grouped_sessions)}\n"
                       f"Reward: {obs.reward}"
            }]
        )
    
    def _handle_tag_pattern(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle tag_pattern tool call."""
        session_name = arguments["session_name"]
        pattern_type = arguments["pattern_type"]
        
        action = NetworkForensicsAction(
            action_type="tag_pattern",
            session_name=session_name,
            pattern_type=pattern_type
        )
        
        obs = self.env.step(action)
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Tagged session '{session_name}' as {pattern_type}.\n"
                       f"All tagged patterns: {list(obs.tagged_patterns.keys())}\n"
                       f"Reward: {obs.reward}"
            }]
        )
    
    def _handle_identify_entry_point(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle identify_entry_point tool call."""
        claimed_entry_point = arguments["claimed_entry_point"]
        
        action = NetworkForensicsAction(
            action_type="identify_entry_point",
            claimed_entry_point=claimed_entry_point
        )
        
        obs = self.env.step(action)
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Identified entry point: {claimed_entry_point}\n"
                       f"Current score: {obs.current_score_estimate}\n"
                       f"Reward: {obs.reward}"
            }]
        )
    
    def _handle_submit_report(self, arguments: Dict[str, Any]) -> MCPCallToolResponse:
        """Handle submit_report tool call."""
        incident_summary = arguments["incident_summary"]
        claimed_entry_point = arguments.get("claimed_entry_point")
        
        action = NetworkForensicsAction(
            action_type="submit_report",
            incident_summary=incident_summary,
            claimed_entry_point=claimed_entry_point
        )
        
        obs = self.env.step(action)
        metrics = obs.metadata or {}
        
        return MCPCallToolResponse(
            content=[{
                "type": "text",
                "text": f"Report submitted successfully!\n"
                       f"Final score: {metrics.get('final_score', obs.current_score_estimate):.3f}\n"
                       f"Success: {'Yes' if metrics.get('success_threshold_met', 0.0) >= 1.0 else 'No'}\n"
                       f"Breakdown: {json.dumps(metrics, indent=2)}"
            }]
        )


# JSON-RPC request model
class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)


def register_mcp_routes(app: FastAPI) -> None:
    """Register MCP routes directly on the given FastAPI app.
    
    This registers routes at /mcp-standard as first-class FastAPI routes
    (not a mounted sub-app). This is necessary because Gradio's mount at
    "/" swallows all paths before sub-app mounts get a chance.
    FastAPI routes always take priority over Starlette mounts.
    """
    server = NetworkForensicsMCPServer()
    
    def _handle_jsonrpc(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle a single JSON-RPC message and return the response."""
        method = message.get("method", "")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        try:
            if method == "initialize":
                request = MCPInitializeRequest(**params)
                response = server.initialize(request)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            elif method == "notifications/initialized":
                return None
            
            elif method == "tools/list":
                response = server.list_tools()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            elif method == "tools/call":
                request = MCPCallToolRequest(**params)
                response = server.call_tool(request)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            elif method == "ping":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {}
                }
            
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
        except Exception as e:
            logger.error(f"JSON-RPC handler error for method '{method}': {e}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
    
    from starlette.requests import Request
    from starlette.responses import Response
    
    @app.post("/mcp-standard", include_in_schema=False)
    async def mcp_jsonrpc_endpoint(request: Request):
        """MCP Streamable HTTP transport — JSON-RPC 2.0 over POST."""
        body = await request.json()
        
        # Handle batch requests
        if isinstance(body, list):
            results = []
            for msg in body:
                result = _handle_jsonrpc(msg)
                if result is not None:
                    results.append(result)
            if results:
                return JSONResponse(content=results)
            return Response(status_code=204)
        
        # Single request
        result = _handle_jsonrpc(body)
        if result is None:
            return Response(status_code=204)
        return JSONResponse(content=result)
    
    @app.get("/mcp-standard", include_in_schema=False)
    async def mcp_endpoint_info():
        """GET on the MCP endpoint — returns server info for discovery."""
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "result": {
                "name": "network-forensics-mcp",
                "version": "1.0.0",
                "protocolVersion": "2024-11-05"
            }
        })
    
    @app.get("/mcp-standard/health", include_in_schema=False)
    async def mcp_health():
        """MCP server health check."""
        return {"status": "ok", "service": "mcp-standard-server"}
    
    logger.info("MCP standard routes registered at /mcp-standard")


# FastAPI application creation
def create_standard_mcp_app() -> FastAPI:
    """Create a FastAPI app with standard MCP endpoints.
    
    This app is designed to be mounted at /mcp-standard, so all routes
    here are relative (no /mcp-standard prefix needed).
    """
    app = FastAPI(title="Network Forensics MCP Standard Server")
    
    # Global server instance (in production, you'd want session management)
    server = NetworkForensicsMCPServer()
    
    def _handle_jsonrpc(message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a single JSON-RPC message and return the response."""
        method = message.get("method", "")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        try:
            if method == "initialize":
                request = MCPInitializeRequest(**params)
                response = server.initialize(request)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            elif method == "notifications/initialized":
                # Client acknowledgement — no response needed for notifications
                return None
            
            elif method == "tools/list":
                response = server.list_tools()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            elif method == "tools/call":
                request = MCPCallToolRequest(**params)
                response = server.call_tool(request)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": response.model_dump()
                }
            
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
        except Exception as e:
            logger.error(f"JSON-RPC handler error for method '{method}': {e}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
    
    # ── Standard MCP Streamable HTTP transport ─────────────────────────
    # MCP clients POST JSON-RPC messages to the root of this mounted app
    # (i.e., POST /mcp-standard when mounted at that path).
    
    from starlette.requests import Request
    from starlette.responses import Response
    
    @app.post("/")
    async def jsonrpc_endpoint(request: Request):
        """Single JSON-RPC endpoint for standard MCP clients.
        
        Handles all MCP methods (initialize, tools/list, tools/call, etc.)
        via JSON-RPC 2.0 over HTTP POST — the Streamable HTTP transport.
        """
        body = await request.json()
        
        # Handle batch requests
        if isinstance(body, list):
            results = []
            for msg in body:
                result = _handle_jsonrpc(msg)
                if result is not None:  # skip notifications
                    results.append(result)
            if results:
                return JSONResponse(content=results)
            return Response(status_code=204)
        
        # Single request
        result = _handle_jsonrpc(body)
        if result is None:
            return Response(status_code=204)
        return JSONResponse(content=result)
    
    @app.get("/")
    async def mcp_endpoint_info():
        """GET on the MCP endpoint — returns server info for discovery."""
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "result": {
                "name": "network-forensics-mcp",
                "version": "1.0.0",
                "description": "Network forensics analysis environment with MCP support",
                "protocolVersion": "2024-11-05"
            }
        })
    
    # ── Convenience REST endpoints (kept for direct testing) ───────────
    
    @app.post("/initialize")
    async def initialize(request: MCPInitializeRequest):
        """Initialize the MCP server."""
        return server.initialize(request)
    
    @app.post("/tools/list")
    async def list_tools():
        """List available MCP tools."""
        return server.list_tools()
    
    @app.post("/tools/call")
    async def call_tool(request: MCPCallToolRequest):
        """Execute an MCP tool."""
        return server.call_tool(request)
    
    # ── WebSocket transport ────────────────────────────────────────────
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time MCP communication."""
        await websocket.accept()
        try:
            while True:
                data = await websocket.receive_text()
                message = json.loads(data)
                result = _handle_jsonrpc(message)
                if result is not None:
                    await websocket.send_text(json.dumps(result))
                    
        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            await websocket.close()
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok", "service": "mcp-standard-server"}
    
    return app


# Standalone server function
def serve(host: str = "0.0.0.0", port: int = 8001):
    """Run the standard MCP server standalone."""
    import uvicorn
    
    app = create_standard_mcp_app()
    logger.info(f"Starting standard MCP server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Forensics MCP Standard Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on")
    parser.add_argument("--task", default="easy", choices=["easy", "medium", "hard"], 
                       help="Default task difficulty")
    
    args = parser.parse_args()
    
    # Create server with specified task
    server = NetworkForensicsMCPServer(task_id=args.task)
    
    serve(host=args.host, port=args.port)