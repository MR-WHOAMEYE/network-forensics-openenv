# Network Forensics MCP Interfaces

This document describes the two MCP (Model Context Protocol) interfaces available in the Network Forensics Environment.

## Overview

The Network Forensics Environment provides **two distinct MCP interfaces** to support different use cases and client compatibility:

1. **Simplified MCP Interface** (`/mcp`) - OpenEnv custom protocol
2. **Standard MCP Interface** (`/mcp-standard`) - Full MCP protocol compliance

## Interface Comparison

| Feature | Simplified MCP (`/mcp`) | Standard MCP (`/mcp-standard`) |
|---------|-------------------------|--------------------------------|
| **Protocol** | OpenEnv custom JSON-RPC | Full MCP specification |
| **Compatibility** | OpenEnv clients | Claude Desktop, Cursor, LangChain |
| **Initialize** | Not required | Required (`/initialize`) |
| **Tool Discovery** | Static | Dynamic (`/tools/list`) |
| **WebSocket** | Custom format | Standard MCP format |
| **Use Case** | Legacy support | Modern MCP clients |

## Simplified MCP Interface (`/mcp`)

**Endpoint**: `http://localhost:8000/mcp`

This interface maintains compatibility with existing OpenEnv clients and provides a simplified JSON-RPC style API.

### Usage
```bash
# HTTP POST
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"action_type": "inspect_packet", "packet_id": "pkt_0001"}'

# WebSocket
ws://localhost:8000/mcp
```

### Tools Available
- `inspect_packet` - Reveal packet payload
- `flag_as_suspicious` - Mark packet as malicious
- `group_into_session` - Group related packets
- `tag_pattern` - Classify attack patterns
- `identify_entry_point` - Find initial compromise
- `submit_report` - Submit final analysis

## Standard MCP Interface (`/mcp-standard`)

**Endpoints**:
- HTTP: `http://localhost:8000/mcp-standard`
- WebSocket: `ws://localhost:8000/mcp-standard/ws`

This interface implements the full MCP specification and is compatible with standard MCP clients like Claude Desktop, Cursor, and LangChain.

### Quick Start

1. **Start the server**:
```bash
python -m server.app
```

2. **Get MCP interface info**:
```bash
curl http://localhost:8000/mcp-info
```

3. **Initialize connection**:
```bash
curl -X POST http://localhost:8000/mcp-standard/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "claude-desktop", "version": "1.0.0"}
  }'
```

4. **List available tools**:
```bash
curl -X POST http://localhost:8000/mcp-standard/tools/list
```

5. **Call a tool**:
```bash
curl -X POST http://localhost:8000/mcp-standard/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "inspect_packet",
    "arguments": {"packet_id": "pkt_0001"}
  }'
```

### Available Tools

#### `reset_env`
Start a new investigation episode.
```json
{
  "name": "reset_env",
  "arguments": {
    "task_id": "easy"  // "easy", "medium", or "hard"
  }
}
```

#### `get_status`
Get current investigation status.
```json
{
  "name": "get_status",
  "arguments": {}
}
```

#### `inspect_packet`
Reveal packet payload for analysis.
```json
{
  "name": "inspect_packet",
  "arguments": {
    "packet_id": "pkt_0001"
  }
}
```

#### `flag_as_suspicious`
Flag a packet as malicious.
```json
{
  "name": "flag_as_suspicious",
  "arguments": {
    "packet_id": "pkt_0001"
  }
}
```

#### `group_into_session`
Group related packets.
```json
{
  "name": "group_into_session",
  "arguments": {
    "session_name": "ddos_attack_1",
    "packet_ids": ["pkt_0001", "pkt_0002", "pkt_0003"]
  }
}
```

#### `tag_pattern`
Classify attack patterns.
```json
{
  "name": "tag_pattern",
  "arguments": {
    "session_name": "ddos_attack_1",
    "pattern_type": "ddos"
  }
}
```

#### `identify_entry_point`
Find initial compromise.
```json
{
  "name": "identify_entry_point",
  "arguments": {
    "claimed_entry_point": "pkt_0001"
  }
}
```

#### `submit_report`
Submit final analysis.
```json
{
  "name": "submit_report",
  "arguments": {
    "incident_summary": "Found DDoS attack targeting...",
    "claimed_entry_point": "pkt_0001"
  }
}
```

## WebSocket Usage (Standard MCP)

For real-time communication, use the WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://localhost:8000/mcp-standard/ws');

ws.onopen = () => {
  // Initialize
  ws.send(JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "claude-desktop", version: "1.0.0" }
    }
  }));
};

ws.onmessage = (event) => {
  const response = JSON.parse(event.data);
  console.log("MCP Response:", response);
};
```

## Testing Both Interfaces

Use the provided test script to verify both interfaces work correctly:

```bash
python test_mcp_interfaces.py
```

This will test:
- ✅ Simplified MCP interface
- ✅ Standard MCP HTTP endpoints
- ✅ Standard MCP WebSocket
- ✅ Complete forensics workflow

## Choosing the Right Interface

### Use Simplified MCP (`/mcp`) when:
- Working with existing OpenEnv clients
- Need backward compatibility
- Prefer simpler JSON-RPC style

### Use Standard MCP (`/mcp-standard`) when:
- Integrating with Claude Desktop
- Building Cursor plugins
- Using LangChain or other MCP-compatible tools
- Need full protocol compliance

## Troubleshooting

### "Method not found: initialize"
**Cause**: Using standard MCP client with simplified interface
**Solution**: Use `/mcp-standard` endpoint instead of `/mcp`

### Connection refused
**Cause**: Server not running
**Solution**: Start the server first:
```bash
python -m server.app
```

### WebSocket connection fails
**Cause**: Port conflicts or firewall issues
**Solution**: Check port 8000 is available and firewall allows WebSocket connections

## Migration Guide

### From Simplified to Standard MCP

1. **Add initialization step**:
   ```bash
   # Old (simplified)
   curl -X POST /mcp -d '{"action_type": "inspect_packet", ...}'
   
   # New (standard)
   curl -X POST /mcp-standard/initialize -d '{...}'
   curl -X POST /mcp-standard/tools/call -d '{"name": "inspect_packet", ...}'
   ```

2. **Use tool discovery**:
   ```bash
   curl -X POST /mcp-standard/tools/list
   ```

3. **Update WebSocket format**:
   ```javascript
   // Old (simplified)
   ws.send(JSON.stringify({"action_type": "inspect_packet", ...}));
   
   // New (standard)
   ws.send(JSON.stringify({
     jsonrpc: "2.0",
     id: 1,
     method: "tools/call",
     params: {name: "inspect_packet", arguments: {...}}
   }));
   ```

## Further Reading

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [OpenEnv Documentation](https://openenv.readthedocs.io/)
- [Network Forensics Environment README](README.md)